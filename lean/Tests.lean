import Merkle
open Vesdb

/-- Toy 32-byte hash (FNV-1a per output byte). Not cryptographic: only for exercising the
    definitions, so `consistency_sound` is known not to be vacuous. -/
def fnv (x : List UInt8) : UInt64 :=
  x.foldl (fun a b => (a ^^^ b.toUInt64) * 1099511628211) 14695981039346656037

def toy : HashFn where
  H x := (List.range 32).map fun i => (fnv (x ++ [i.toUInt8]) >>> 17).toUInt8
  len32 x := by simp

def leaves (n : Nat) (salt : UInt8 := 0) : List Bytes := (List.range n).map fun i => [i.toUInt8, salt]

/-- Honest proofs verify for every 0 ≤ m ≤ n ≤ N. -/
def honest (N : Nat) : Bool :=
  (List.range (N + 1)).all fun n => (List.range (n + 1)).all fun m =>
    let l := leaves n
    verifyConsistency toy m n (mth toy (l.take m)) (mth toy l) (consistencyProof toy m l)

/-- The same proofs fail when one old leaf differs (a forked history). -/
def forked (N : Nat) : Bool :=
  (List.range (N + 1)).all fun n => (List.range n).all fun m => (List.range m).all fun i =>
    let l := leaves n
    let old := (l.take m).set i [i.toUInt8, 99]
    !verifyConsistency toy m n (mth toy old) (mth toy l) (consistencyProof toy m l)

#guard honest 24
#guard forked 16
-- RFC 9162 example sizes: proof lengths for (3, 7), (4, 7), (6, 7)
#guard (consistencyProof toy 3 (leaves 7)).length = 4
#guard (consistencyProof toy 4 (leaves 7)).length = 1
#guard (consistencyProof toy 6 (leaves 7)).length = 3
