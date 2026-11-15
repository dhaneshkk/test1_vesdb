/-
  Differential vectors: the Lean definitions the theorems are about (`mth`, `consistencyProof`,
  `verifyConsistency`, `inclusionProof`, `verifyInclusion`), evaluated with real SHA-256.
  `crates/vesdb-core/tests/lean_vectors.rs` requires the Rust implementation to agree on every
  root, every proof, and the accept/reject verdict for every case.

  Run: LEAN_PATH=<lean lib>:. lean --run Vectors.lean <out.json> [N]
-/
import Sha256
open Vesdb

def sha := Sha256.hashFn
def hex := Sha256.hex

/-- Leaf `i` is the two bytes `[i / 256, i % 256]`. -/
def leaves (n : Nat) : List Bytes := (List.range n).map fun i => [(i / 256).toUInt8, (i % 256).toUInt8]

def tweak (b : Bytes) : Bytes := match b with
  | [] => [1]
  | x :: xs => (x ^^^ 1) :: xs

def flipAt (p : List Bytes) (i : Nat) : List Bytes := p.modify i tweak

def jstr (s : String) : String := "\"" ++ s ++ "\""
def jarr (xs : List String) : String := "[" ++ ",".intercalate xs ++ "]"
def jhexes (p : List Bytes) : String := jarr (p.map fun b => jstr (hex b))
def jcase (kind : String) (at_ : Option Nat) (ok : Bool) : String :=
  "{\"kind\":" ++ jstr kind ++ (match at_ with | some i => ",\"at\":" ++ toString i | none => "")
    ++ ",\"expected\":" ++ toString ok ++ "}"

def consistencyCases (roots : List Bytes) (m n : Nat) (p : List Bytes) : List String :=
  let root (k : Nat) := roots.getD k []
  let v (m' n' : Nat) (o r : Bytes) (q : List Bytes) := verifyConsistency sha m' n' o r q
  let o := root m
  let r := root n
  [jcase "honest" none (v m n o r p)] ++
  ((List.range p.length).map fun i => jcase "flip" (some i) (v m n o r (flipAt p i))) ++
  [jcase "drop" none (v m n o r p.dropLast),
   jcase "extra" none (v m n o r (p ++ [List.replicate 32 0])),
   jcase "dup" none (v m n o r (p.take 1 ++ p)),
   jcase "old" none (v m n (tweak o) r p),
   jcase "new" none (v m n o (tweak r) p),
   jcase "m+1" none (v (m + 1) n o r p),
   jcase "n+1" none (v m (n + 1) o r p),
   jcase "m-1" none (v (m - 1) n o r p)]

def inclusionCases (roots : List Bytes) (ls : List Bytes) (i n : Nat) (p : List Bytes) :
    List String :=
  let r := roots.getD n []
  let leaf := leafHash sha (ls.getD i [])
  let v (i' n' : Nat) (lf rt : Bytes) (q : List Bytes) := verifyInclusion sha i' n' lf rt q
  [jcase "honest" none (v i n leaf r p)] ++
  ((List.range p.length).map fun j => jcase "flip" (some j) (v i n leaf r (flipAt p j))) ++
  [jcase "drop" none (v i n leaf r p.dropLast),
   jcase "extra" none (v i n leaf r (p ++ [List.replicate 32 0])),
   jcase "leaf" none (v i n (tweak leaf) r p),
   jcase "root" none (v i n leaf (tweak r) p),
   jcase "i+1" none (v (i + 1) n leaf r p),
   jcase "i-1" none (v (i - 1) n leaf r p),
   jcase "n+1" none (v i (n + 1) leaf r p),
   jcase "n-1" none (v i (n - 1) leaf r p)]

def main (args : List String) : IO Unit := do
  let out := args.getD 0 "lean_vectors.json"
  let N := (args.getD 1 "32").toNat!
  let ls := leaves (N + 1)
  let roots := (List.range (N + 2)).map fun n => mth sha (ls.take n)
  let mut cons : Array String := #[]
  let mut incl : Array String := #[]
  let mut cases := 0
  for n in [0:N + 1] do
    let l := ls.take n
    for m in [0:n + 1] do
      let p := consistencyProof sha m l
      let cs := consistencyCases roots m n p
      cases := cases + cs.length
      cons := cons.push ("{\"m\":" ++ toString m ++ ",\"n\":" ++ toString n ++ ",\"proof\":"
        ++ jhexes p ++ ",\"cases\":" ++ jarr cs ++ "}")
    for i in [0:n] do
      let p := inclusionProof sha i l
      let cs := inclusionCases roots l i n p
      cases := cases + cs.length
      incl := incl.push ("{\"i\":" ++ toString i ++ ",\"n\":" ++ toString n ++ ",\"proof\":"
        ++ jhexes p ++ ",\"cases\":" ++ jarr cs ++ "}")
  let json := "{\"generator\":\"lean/Vectors.lean\",\"leaf\":\"[i / 256, i % 256]\",\"N\":"
    ++ toString N ++ ",\"roots\":" ++ jhexes roots ++ ",\"consistency\":"
    ++ jarr cons.toList ++ ",\"inclusion\":" ++ jarr incl.toList ++ "}"
  IO.FS.writeFile out json
  IO.println s!"wrote {out}: {cons.size} consistency pairs, {incl.size} inclusion pairs, {cases} cases"
