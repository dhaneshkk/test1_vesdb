/-
  VesdbStore — single-writer log on a shared bucket (high-availability plan, "Formal guarantees").

  Model. The bucket is a partial map from positions to batches. Any number of servers each keep
  their own view (the batches they applied). A server writes only at the end of its own view,
  and only with create-only-if-new; it acknowledges only after the create succeeded. Servers may
  also tail the bucket, restart from nothing, and redaction may change payload objects at any
  time. Steps interleave arbitrarily, which also models pauses and lost messages.

  Atomicity of create-if-new is not an axiom here: in an interleaving semantics every step is
  atomic, so "of two creates at one position at most one succeeds" is part of the step
  definitions. That a real store behaves this way is what the race test checks.

  Checked with official Lean 4.25.0, core library only, no `sorry`, standard axioms only.
-/
import Merkle
open Vesdb

namespace VesdbStore

structure Batch where
  leaves : List Bytes
  /-- idempotency key of the request that produced the batch -/
  key    : Option Nat
  /-- root in the batch's signed receipt -/
  root   : Bytes

def allLeaves (bs : List Batch) : List Bytes := bs.flatMap (·.leaves)

structure Sys where
  bucket : Nat → Option Batch
  view   : Nat → List Batch
  acked  : List (Nat × Batch)
  data   : Nat → Bytes

def init : Sys := ⟨fun _ => none, fun _ => [], [], fun _ => []⟩

/-- Bucket after a successful create at `p`. -/
def put (f : Nat → Option Batch) (p : Nat) (b : Batch) : Nat → Option Batch :=
  fun q => if q = p then some b else f q

def setView (v : Nat → List Batch) (i : Nat) (l : List Batch) : Nat → List Batch :=
  fun j => if j = i then l else v j

/-- The batches at positions `0 … p-1`, in order (skipping holes, of which there are none). -/
def upTo (f : Nat → Option Batch) (p : Nat) : List Batch := (List.range p).filterMap f

inductive Step (h : HashFn) : Sys → Sys → Prop
  /-- Server `i` writes leaves `ls` with key `k`: its own view has no batch with that key, the
      create at the end of its view succeeds, and only then is the batch acknowledged. The
      receipt root is computed over the server's own view. -/
  | write (s : Sys) (i : Nat) (ls : List Bytes) (k : Option Nat)
      (hkey : ∀ b ∈ s.view i, k ≠ none → b.key ≠ k)
      (hfree : s.bucket (s.view i).length = none) :
      Step h s
        (let b : Batch := ⟨ls, k, mth h (allLeaves (s.view i) ++ ls)⟩
         { s with bucket := put s.bucket (s.view i).length b
                  view := setView s.view i (s.view i ++ [b])
                  acked := ((s.view i).length, b) :: s.acked })
  /-- Server `i` applies the next stored batch. -/
  | tail (s : Sys) (i : Nat) (b : Batch) (hb : s.bucket (s.view i).length = some b) :
      Step h s { s with view := setView s.view i (s.view i ++ [b]) }
  /-- Server `i` restarts and has applied nothing. -/
  | restart (s : Sys) (i : Nat) : Step h s { s with view := setView s.view i [] }
  /-- Redaction replaces payload objects; log objects are untouched. -/
  | redact (s : Sys) (d : Nat → Bytes) : Step h s { s with data := d }

inductive Reach (h : HashFn) : Sys → Prop
  | init : Reach h init
  | step {s t : Sys} : Reach h s → Step h s t → Reach h t

/-! ### The invariant -/

structure Inv (h : HashFn) (s : Sys) : Prop where
  /-- the bucket holds exactly positions `0 … n-1` -/
  contig : ∃ n, ∀ p, (s.bucket p).isSome ↔ p < n
  /-- every server's view is the bucket's first batches -/
  view_ok : ∀ i k, k < (s.view i).length → s.bucket k = (s.view i)[k]?
  ack_ok : ∀ pb ∈ s.acked, s.bucket pb.1 = some pb.2
  root_ok : ∀ p b, s.bucket p = some b → b.root = mth h (allLeaves (upTo s.bucket p) ++ b.leaves)
  key_ok : ∀ p q b c, s.bucket p = some b → s.bucket q = some c → b.key = c.key →
    b.key ≠ none → p = q

theorem inv_init (h : HashFn) : Inv h init :=
  ⟨⟨0, by simp [init]⟩, by simp [init], by simp [init], by simp [init], by simp [init]⟩

theorem upTo_succ (f : Nat → Option Batch) (p : Nat) :
    upTo f (p + 1) = upTo f p ++ (f p).toList := by
  unfold upTo
  rw [List.range_succ, List.filterMap_append]
  cases hp : f p <;> simp [hp]

/-- A view that agrees with the bucket on its positions is `upTo` its length. -/
theorem upTo_view (f : Nat → Option Batch) (v : List Batch)
    (hv : ∀ k, k < v.length → f k = v[k]?) : upTo f v.length = v := by
  have : ∀ m, m ≤ v.length → upTo f m = v.take m := by
    intro m
    induction m with
    | zero => intro _; simp [upTo]
    | succ m ih =>
      intro hm
      rw [upTo_succ, ih (by omega), hv m (by omega), List.take_succ]
  rw [this _ (Nat.le_refl _), List.take_length]

theorem upTo_congr (f g : Nat → Option Batch) (p : Nat) (e : ∀ q < p, f q = g q) :
    upTo f p = upTo g p := by
  induction p with
  | zero => simp [upTo]
  | succ p ih =>
    rw [upTo_succ, upTo_succ, ih (fun q hq => e q (by omega)), e p (by omega)]

theorem inv_step (h : HashFn) {s t : Sys} (hi : Inv h s) (st : Step h s t) : Inv h t := by
  obtain ⟨⟨n, hn⟩, hview, hack, hroot, hkey⟩ := hi
  -- a view only holds positions the bucket has
  have inb : ∀ j q, q < (s.view j).length → q < n := fun j q hq => by
    have := hview j q hq
    rw [List.getElem?_eq_getElem hq] at this
    exact (hn q).mp (by simp [this])
  cases st with
  | write i ls k hk hfree =>
    dsimp only
    generalize hbdef : (⟨ls, k, mth h (allLeaves (s.view i) ++ ls)⟩ : Batch) = b
    generalize hL : (s.view i).length = L at hfree
    -- the create succeeded at the end of i's view, so i's view is the whole bucket
    have hLn : L = n := by
      have h1 : ¬ L < n := by rw [← hn]; simp [hfree]
      have h2 : ¬ n < L := fun hlt => h1 (by have := inb i n (by omega); omega)
      omega
    have hup : upTo s.bucket L = s.view i := hL ▸ upTo_view _ _ (hview i)
    have hlt : ∀ q c, s.bucket q = some c → q < L := fun q c hq => by
      rw [hLn]; exact (hn q).mp (by simp [hq])
    have mem : ∀ q c, s.bucket q = some c → c ∈ s.view i := fun q c hq => by
      have := hview i q (by have := hlt q c hq; omega)
      rw [hq] at this
      exact List.mem_of_getElem? this.symm
    refine ⟨⟨n + 1, fun q => ?_⟩, ?_, ?_, ?_, ?_⟩
    · simp only [put]
      by_cases hq : q = L
      · simp [hq]; omega
      · simp [hq, hn]; omega
    · intro j q hq
      simp only [setView, put] at hq ⊢
      by_cases hj : j = i
      · subst hj
        simp only [if_true, List.length_append, List.length_singleton] at hq ⊢
        by_cases hqp : q = L
        · subst hqp; simp [← hL]
        · rw [if_neg hqp, hview j q (by omega), List.getElem?_append_left (by omega)]
      · rw [if_neg hj] at hq ⊢
        have hne : q ≠ L := by have := inb j q hq; omega
        rw [if_neg hne, hview j q hq]
    · intro pb hpb
      simp only [List.mem_cons] at hpb
      rcases hpb with rfl | hpb
      · simp [put]
      · have := hack pb hpb
        have hne : pb.1 ≠ L := fun e => by rw [e, hfree] at this; simp at this
        simp [put, hne, this]
    · intro q c hc
      have hupq : upTo (put s.bucket L b) q = upTo s.bucket q := by
        apply upTo_congr
        intro r hr
        have hrp : r ≠ L := by
          intro e; subst e
          by_cases hqp : q = r
          · omega
          · simp only [put, if_neg hqp] at hc
            have := hlt q c hc; omega
        simp [put, hrp]
      rw [hupq]
      simp only [put] at hc
      by_cases hqp : q = L
      · rw [if_pos hqp] at hc
        simp only [Option.some.injEq] at hc
        subst hc; subst hqp; rw [hup, ← hbdef]
      · rw [if_neg hqp] at hc
        exact hroot q c hc
    · intro q r b' c hb hc hbc hne
      simp only [put] at hb hc
      have hbk : b.key = k := by rw [← hbdef]
      by_cases hq : q = L <;> by_cases hr : r = L
      · omega
      · rw [if_pos hq] at hb; rw [if_neg hr] at hc
        simp only [Option.some.injEq] at hb; subst hb
        exact absurd hbc (by rw [hbk]; exact fun e => hk c (mem r c hc) (by rwa [← hbk]) e.symm)
      · rw [if_neg hq] at hb; rw [if_pos hr] at hc
        simp only [Option.some.injEq] at hc; subst hc
        exact absurd hbc (by rw [hbk]; exact hk b' (mem q b' hb) (by rwa [hbc, hbk] at hne))
      · rw [if_neg hq] at hb; rw [if_neg hr] at hc
        exact hkey q r b' c hb hc hbc hne
  | tail i b hb =>
    refine ⟨⟨n, hn⟩, ?_, hack, hroot, hkey⟩
    intro j q hq
    simp only [setView] at hq ⊢
    by_cases hj : j = i
    · subst hj
      simp only [if_true, List.length_append, List.length_singleton] at hq ⊢
      by_cases hqp : q = (s.view j).length
      · subst hqp; simp [hb]
      · rw [hview j q (by omega), List.getElem?_append_left (by omega)]
    · rw [if_neg hj] at hq ⊢; exact hview j q hq
  | restart i =>
    refine ⟨⟨n, hn⟩, ?_, hack, hroot, hkey⟩
    intro j q hq
    simp only [setView] at hq ⊢
    by_cases hj : j = i
    · rw [if_pos hj] at hq; simp at hq
    · rw [if_neg hj] at hq ⊢; exact hview j q hq
  | redact d => exact ⟨⟨n, hn⟩, hview, hack, hroot, hkey⟩

theorem reach_inv (h : HashFn) {s : Sys} (r : Reach h s) : Inv h s := by
  induction r with
  | init => exact inv_init h
  | step _ st ih => exact inv_step h ih st

/-! ### The plan's theorems -/

/-- **no_fork**: no two acknowledged batches share a position. -/
theorem no_fork (h : HashFn) {s : Sys} (r : Reach h s) {p : Nat} {b c : Batch}
    (hb : (p, b) ∈ s.acked) (hc : (p, c) ∈ s.acked) : b = c := by
  have i := reach_inv h r
  have e1 := i.ack_ok _ hb
  have e2 := i.ack_ok _ hc
  simp only at e1 e2
  rw [e1] at e2
  exact Option.some.inj e2

/-- **prefix**: any two servers' applied logs are prefixes of one another. -/
theorem views_prefix (h : HashFn) {s : Sys} (r : Reach h s) (i j : Nat) :
    s.view i <+: s.view j ∨ s.view j <+: s.view i := by
  have hi := reach_inv h r
  have ei := upTo_view _ _ (hi.view_ok i)
  have ej := upTo_view _ _ (hi.view_ok j)
  have key : ∀ a b : Nat, a ≤ b → upTo s.bucket a <+: upTo s.bucket b := fun a b hab => by
    unfold upTo
    rw [show b = a + (b - a) by omega, List.range_add, List.filterMap_append]
    exact List.prefix_append _ _
  rcases Nat.le_total (s.view i).length (s.view j).length with hle | hle
  · exact .inl (ei ▸ ej ▸ key _ _ hle)
  · exact .inr (ej ▸ ei ▸ key _ _ hle)

/-- **ack_durable**: every acknowledged batch is in the bucket. -/
theorem ack_durable (h : HashFn) {s : Sys} (r : Reach h s) :
    ∀ pb ∈ s.acked, s.bucket pb.1 = some pb.2 :=
  (reach_inv h r).ack_ok

/-- **receipt_sound**: every stored batch's receipt root is the Merkle root of the log up to and
    including it. With `consistency_sound`, receipts of later batches extend earlier ones. -/
theorem receipt_sound (h : HashFn) {s : Sys} (r : Reach h s) {p : Nat} {b : Batch}
    (hb : s.bucket p = some b) : b.root = mth h (allLeaves (upTo s.bucket (p + 1))) := by
  rw [(reach_inv h r).root_ok p b hb]
  simp [upTo, List.range_succ, List.filterMap_append, hb, allLeaves, List.flatMap_append]

/-- **idempotent**: a request's key is stored at most once, however many servers it was retried
    on, so a repeated write never adds a second copy. -/
theorem idempotent (h : HashFn) {s : Sys} (r : Reach h s) {p q : Nat} {b c : Batch} {k : Nat}
    (hb : s.bucket p = some b) (hc : s.bucket q = some c) (hk1 : b.key = some k)
    (hk2 : c.key = some k) : p = q :=
  (reach_inv h r).key_ok p q b c hb hc (hk1.trans hk2.symm) (by simp [hk1])

/-- **redaction_keeps_proofs**: redaction changes no log object, so no leaf, root, receipt or
    checkpoint changes. -/
theorem redaction_keeps_proofs (h : HashFn) (s : Sys) (d : Nat → Bytes) :
    ∃ t, Step h s t ∧ t.bucket = s.bucket ∧ t.view = s.view ∧ t.acked = s.acked ∧ t.data = d :=
  ⟨_, .redact s d, rfl, rfl, rfl, rfl⟩

end VesdbStore

namespace VesdbStore

/-- Not vacuous: server 0 writes, server 1 catches up by tailing and writes after it; both
    batches are acknowledged, at positions 0 and 1. (Server 1 could not have written first at
    position 0: that step needs the position to be free.) -/
theorem two_writers_take_turns (h : HashFn) (x y : Bytes) :
    ∃ s, Reach h s ∧ s.acked.map (·.1) = [1, 0] := by
  have s0 := Reach.init (h := h)
  have s1 := Reach.step s0 (Step.write init 0 [x] none (by simp [init]) (by simp [init]))
  have s2 := Reach.step s1 (Step.tail _ 1 ⟨[x], none, mth h (allLeaves [] ++ [x])⟩
    (by simp [init, put, setView]))
  have s3 := Reach.step s2 (Step.write _ 1 [y] none (by simp) (by simp [init, put, setView]))
  exact ⟨_, s3, by simp [init, put, setView]⟩

end VesdbStore
