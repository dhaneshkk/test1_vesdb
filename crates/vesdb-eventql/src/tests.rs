use super::*;
use serde_json::json;

const T0: u64 = 1_792_400_000_000_000_000; // 2026-10-20T00:00:00Z (approx day boundary set below)

fn day(d: u32, h: u32) -> u64 {
    // 2026-10-<d>T<h>:00:00Z
    vesdb_core::time::parse_rfc3339_ns(&format!("2026-10-{d:02}T{h:02}:00:00Z")).unwrap()
}

fn catalog() -> Catalog {
    let _ = T0;
    let rows: Vec<(u64, &str, &str, Option<&str>)> = vec![
        (
            day(19, 9),
            "/books/42",
            "io.eventsourcingdb.library.book-acquired",
            Some(r#"{"title":"2001","total":120,"tags":["sf","classic"],"book-id":"42"}"#),
        ),
        (
            day(20, 10),
            "/books/42",
            "io.eventsourcingdb.library.book-borrowed",
            Some(r#"{"reader":"/readers/23","rating":5}"#),
        ),
        (
            day(20, 11),
            "/books/7",
            "io.eventsourcingdb.library.book-acquired",
            Some(r#"{"title":"Dune","total":80}"#),
        ),
        (
            day(20, 23),
            "/books/42",
            "io.eventsourcingdb.library.book-borrowed",
            Some(r#"{"reader":"/readers/24","rating":3}"#),
        ),
        (
            day(21, 8),
            "/readers/23",
            "io.eventsourcingdb.library.book-borrowed",
            Some(r#"{"book":"/books/7","rating":4}"#),
        ),
        (
            day(21, 9),
            "/books/7",
            "io.eventsourcingdb.library.book-borrowed",
            None,
        ), // redacted
    ];
    let hashes: Vec<String> = (0..rows.len())
        .map(|i| format!("esdb:hash:v2:{i:064}"))
        .collect();
    let ev: Vec<EventRow> = rows
        .iter()
        .enumerate()
        .map(|(i, (t, s, ty, d))| EventRow {
            id: i as u64,
            time_ns: *t,
            source: "https://library.eventsourcingdb.io",
            subject: s,
            ty,
            data: *d,
            predecessorhash: if i == 0 { "0" } else { &hashes[i - 1] },
            hash: &hashes[i],
            traceparent: None,
            tracestate: None,
        })
        .collect();
    let mut subjects: Vec<String> = rows.iter().map(|r| r.1.to_string()).collect();
    subjects.sort();
    subjects.dedup();
    let mut types: Vec<String> = rows.iter().map(|r| r.2.to_string()).collect();
    types.sort();
    types.dedup();
    Catalog {
        events: vec![events_batch(&ev)],
        subjects,
        event_types: types,
    }
}

fn q(s: &str) -> Vec<Value> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(run(s, &catalog(), &Limits::default()))
        .unwrap_or_else(|e| panic!("{s}\n=> {e}"))
}

fn qerr(s: &str) -> Error {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(run(s, &catalog(), &Limits::default()))
        .expect_err(s)
}

#[test]
fn most_recent_events() {
    let r = q("FROM e IN events ORDER BY e.id AS INT DESC TOP 2 PROJECT INTO e");
    assert_eq!(r.len(), 2);
    assert_eq!(r[0]["id"], "5");
    assert_eq!(r[1]["id"], "4");
    assert_eq!(r[0]["data"], Value::Null, "redacted payload");
    assert_eq!(r[1]["data"]["book"], "/books/7");
    assert_eq!(r[1]["time"], "2026-10-21T08:00:00.000000000Z");
    assert_eq!(r[1]["specversion"], "1.0");
}

#[test]
fn guarded_ratings() {
    let r = q(r#"FROM e IN events
                 WHERE e.subject == "/books/42" AND e.data.rating != NULL AND e.data.rating >= 4
                 ORDER BY e.time DESC TOP 5
                 PROJECT INTO { id: e.id, rating: e.data.rating, at: e.time }"#);
    assert_eq!(
        r,
        vec![json!({"id": "1", "rating": 5, "at": "2026-10-20T10:00:00.000000000Z"})]
    );
}

#[test]
fn unguarded_null_fails_like_eventql() {
    // without the != NULL guard the comparison meets NULL in WHERE: a strict boolean is required
    assert!(matches!(
        qerr("FROM e IN events WHERE e.data.rating >= 4 PROJECT INTO e.id"),
        Error::Unevaluable(_)
    ));
}

#[test]
fn count_per_type_in_first_row_order() {
    let r = q(
        "FROM e IN events GROUP BY e.type PROJECT INTO { type: UNIQUE(e.type), count: COUNT() }",
    );
    assert_eq!(
        r,
        vec![
            json!({"type": "io.eventsourcingdb.library.book-acquired", "count": 2}),
            json!({"type": "io.eventsourcingdb.library.book-borrowed", "count": 4}),
        ]
    );
}

#[test]
fn one_day_with_datetime_range() {
    let r = q(r#"FROM e IN events
                 WHERE e.time >= "2026-10-20T00:00:00Z" AS DATETIME AND e.time < "2026-10-21T00:00:00Z" AS DATETIME
                 PROJECT INTO { id: e.id, type: e.type }"#);
    let ids: Vec<&str> = r.iter().map(|v| v["id"].as_str().unwrap()).collect();
    assert_eq!(ids, vec!["1", "2", "3"]);
}

#[test]
fn subquery_then_filter() {
    let r = q(r#"FROM o IN (
                   FROM e IN events
                   WHERE e.type == "io.eventsourcingdb.library.book-acquired" AND e.data.total != NULL
                   PROJECT INTO { orderId: e.id, value: e.data.total }
                 )
                 WHERE o.value > 100
                 PROJECT INTO o"#);
    assert_eq!(r, vec![json!({"orderId": "0", "value": 120})]);
}

#[test]
fn cartesian_join_by_filter() {
    let r = q(r#"FROM a IN events
                 FROM b IN events
                 WHERE a.subject == b.subject
                   AND a.type == "io.eventsourcingdb.library.book-acquired"
                   AND b.type == "io.eventsourcingdb.library.book-borrowed"
                 PROJECT INTO { acquired: a.id, borrowed: b.id }"#);
    assert_eq!(
        r,
        vec![
            json!({"acquired": "0", "borrowed": "1"}),
            json!({"acquired": "0", "borrowed": "3"}),
            json!({"acquired": "2", "borrowed": "5"})
        ]
    );
}

#[test]
fn time_buckets_and_having() {
    let r = q("FROM e IN events GROUP BY DAY(e.time) HAVING COUNT() > 1 PROJECT INTO { day: UNIQUE(DAY(e.time)), n: COUNT() }");
    assert_eq!(
        r,
        vec![json!({"day": 20, "n": 3}), json!({"day": 21, "n": 2})]
    );
    let r = q("FROM e IN events GROUP BY WEEKDAY(e.time) PROJECT INTO { wd: UNIQUE(WEEKDAY(e.time)), n: COUNT() }");
    // 2026-10-19 is a Monday (1), 20 Tue (2), 21 Wed (3)
    assert_eq!(r[0], json!({"wd": 1, "n": 1}));
}

#[test]
fn whole_set_aggregates() {
    let r = q("FROM e IN events WHERE e.data.rating != NULL PROJECT INTO { n: COUNT(), avg: AVG(e.data.rating), min: MIN(e.data.rating), max: MAX(e.data.rating), median: MEDIAN(e.data.rating), sum: SUM(e.data.rating) }");
    assert_eq!(
        r,
        vec![json!({"n": 3, "avg": 4.0, "min": 3.0, "max": 5.0, "median": 4.0, "sum": 12.0})]
    );
    // COUNT over nothing is 0, AVG over nothing fails
    assert_eq!(
        q(r#"FROM e IN events WHERE e.type == "x.y.z" PROJECT INTO COUNT()"#),
        vec![json!(0)]
    );
    assert!(matches!(
        qerr(r#"FROM e IN events WHERE e.type == "x.y.z" PROJECT INTO AVG(e.data.rating)"#),
        Error::Unevaluable(_)
    ));
    // UNIQUE over several values fails
    assert!(matches!(
        qerr("FROM e IN events PROJECT INTO UNIQUE(e.subject)"),
        Error::Unevaluable(_)
    ));
}

#[test]
fn paths_indexes_and_keys() {
    let r = q(
        r#"FROM e IN events WHERE e.data.tags != NULL PROJECT INTO [e.data.tags[0], e.data.tags[-1], e.data["book-id"], e.data.missing]"#,
    );
    assert_eq!(r, vec![json!(["sf", "classic", "42", null])]);
}

#[test]
fn strings_math_casts_if() {
    let r = q(r#"FROM e IN events WHERE e.id == "0" PROJECT INTO {
        up: UPPER(e.data.title), len: LEN(e.subject), sw: STARTSWITH(e.subject, "/books"),
        sub: SUBSTRING(e.subject, 1, 5), at: INSTR(e.subject, "42"), rep: REPLACE(e.subject, "books", "b"),
        idn: e.id AS INT, f: (e.data.total AS FLOAT64) / 8, s: e.data.total AS STRING, cat: "x" + e.id,
        big: IF(e.data.total > 100, "big", "small"), abs: ABS(-3), pw: POW(2, 10), yr: YEAR(e.time)
    }"#);
    assert_eq!(
        r[0],
        json!({"up": "2001", "len": 9, "sw": true, "sub": "books", "at": 7, "rep": "/b/42",
               "idn": 0, "f": 15.0, "s": "120", "cat": "x0", "big": "big", "abs": 3, "pw": 1024.0, "yr": 2026})
    );
}

#[test]
fn distinct_skip_top() {
    let r = q("FROM e IN events PROJECT INTO DISTINCT e.subject");
    assert_eq!(
        r,
        vec![json!("/books/42"), json!("/books/7"), json!("/readers/23")]
    );
    let r = q("FROM e IN events SKIP 1 TOP 2 PROJECT INTO e.id");
    assert_eq!(r, vec![json!("1"), json!("2")]);
}

#[test]
fn subjects_and_eventtypes_sources() {
    let r = q(r#"FROM s IN subjects WHERE STARTSWITH(s, "/books") PROJECT INTO s"#);
    assert_eq!(r, vec![json!("/books/42"), json!("/books/7")]);
    assert_eq!(
        q("FROM t IN eventtypes PROJECT INTO COUNT()"),
        vec![json!(2)]
    );
}

#[test]
fn dcb_rule_as_boolean_query() {
    // "a reader may borrow fewer than three books": precondition query
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let cat = catalog();
    let ok = rt
        .block_on(eval_bool(
            r#"FROM e IN events WHERE e.type == "io.eventsourcingdb.library.book-borrowed" AND e.data.reader != NULL AND e.data.reader == "/readers/23" PROJECT INTO COUNT() < 3"#,
            &cat,
            &Limits::default(),
        ))
        .unwrap();
    assert!(ok);
    let not_bool = rt.block_on(eval_bool(
        "FROM e IN events PROJECT INTO e.id",
        &cat,
        &Limits::default(),
    ));
    assert!(matches!(not_bool, Err(Error::NotBoolean)));
}

#[test]
fn plan_is_a_datafusion_logical_plan() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let p = rt.block_on(explain(r#"FROM e IN events WHERE e.subject == "/books/42" ORDER BY e.time DESC TOP 1 PROJECT INTO e.data.title"#, &catalog())).unwrap();
    for op in [
        "Limit",
        "Sort",
        "Projection",
        "WindowAggr",
        "Filter",
        "TableScan: e",
    ] {
        assert!(p.contains(op), "missing {op} in plan:\n{p}");
    }
}

/// Queries at the nesting and operand limits must not crash a 2 MiB worker thread (DoS guard).
#[test]
fn limits_do_not_overflow_the_stack() {
    let h = std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(|| {
            let nested = format!(
                "FROM e IN events WHERE e.id == \"0\" PROJECT INTO {}1{}",
                "(".repeat(250),
                ")".repeat(250)
            );
            assert_eq!(q(&nested), vec![json!(1)]);
            let sum = format!(
                "FROM e IN events WHERE e.id == \"0\" PROJECT INTO {}",
                vec!["1"; 1_000].join(" + ")
            );
            assert_eq!(q(&sum), vec![json!(1_000)]);
            let too_many = format!(
                "FROM e IN events PROJECT INTO {}",
                vec!["1"; 1_002].join(" + ")
            );
            assert!(
                matches!(
                    qerr(&too_many),
                    Error::TooLong | Error::Malformed(_) | Error::TooDeep
                ),
                "operand cap"
            );
            let too_deep = format!(
                "FROM e IN events PROJECT INTO {}1{}",
                "(".repeat(300),
                ")".repeat(300)
            );
            assert!(matches!(qerr(&too_deep), Error::TooDeep));
        })
        .unwrap();
    h.join().expect("no stack overflow");
}

#[test]
fn timeout_releases_the_caller() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let sum = format!(
        "FROM e IN events PROJECT INTO {}",
        vec!["1"; 1_000].join(" + ")
    );
    let limits = Limits {
        timeout: Duration::from_millis(1),
        ..Default::default()
    };
    let t = std::time::Instant::now();
    let r = rt.block_on(run(&sum, &catalog(), &limits));
    assert!(matches!(r, Err(Error::Unevaluable(_))));
    assert!(
        t.elapsed() < Duration::from_secs(5),
        "caller released after the timeout, took {:?}",
        t.elapsed()
    );
}
