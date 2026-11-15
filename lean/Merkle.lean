/-
  vesdb — RFC 9162 Merkle trees: definitions and consistency-proof soundness.

  Checked with official Lean 4.25.0, core library only (no Mathlib, no `sorry`, no axioms beyond
  Lean's standard three). Definitions follow the design doc ("Lean 4 formalisation", §2), with one
  change: `split` uses core's `Nat.log2` instead of Mathlib's `Nat.log 2` (the same function).
-/
namespace Vesdb

abbrev Bytes := List UInt8

/-- SHA-256 as a black box. No injectivity is assumed: theorems conclude `P ∨ Collision h`. -/
structure HashFn where
  H     : Bytes → Bytes
  len32 : ∀ x, (H x).length = 32

def Collision (h : HashFn) : Prop := ∃ a b : Bytes, a ≠ b ∧ h.H a = h.H b

def leafHash (h : HashFn) (x : Bytes) : Bytes := h.H (0x00 :: x)
def nodeHash (h : HashFn) (l r : Bytes) : Bytes := h.H (0x01 :: (l ++ r))

/-- Largest power of two strictly below `n`, for `n ≥ 2` (RFC 9162 §2.1.1). -/
def split (n : Nat) : Nat := 2 ^ Nat.log2 (n - 1)

theorem split_pos (n : Nat) : 0 < split n := Nat.pow_pos (by decide)

theorem split_lt {n : Nat} (hn : 2 ≤ n) : split n < n := by
  have := Nat.log2_self_le (n := n - 1) (by omega)
  unfold split; omega

/-- `split n = 2^k` exactly when `2^k < n ≤ 2^(k+1)`. -/
theorem split_eq {n k : Nat} (h1 : 2 ^ k < n) (h2 : n ≤ 2 ^ (k + 1)) : split n = 2 ^ k := by
  unfold split
  have hne : n - 1 ≠ 0 := by have := Nat.one_le_two_pow (n := k); omega
  have hle : k ≤ (n - 1).log2 := (Nat.le_log2 hne).2 (by omega)
  have hlt : (n - 1).log2 < k + 1 := (Nat.log2_lt hne).2 (by omega)
  rw [show (n - 1).log2 = k by omega]

/-- Merkle Tree Hash, RFC 9162 §2.1.1. -/
def mth (h : HashFn) : List Bytes → Bytes
  | []  => h.H []
  | [x] => leafHash h x
  | x :: y :: t =>
      nodeHash h (mth h ((x :: y :: t).take (split (t.length + 2))))
        (mth h ((x :: y :: t).drop (split (t.length + 2))))
termination_by l => l.length
decreasing_by
  all_goals
    simp only [List.length_take, List.length_drop, List.length_cons]
    have := split_pos (t.length + 2)
    have := split_lt (n := t.length + 2) (by omega)
    omega

theorem mth_nil (h : HashFn) : mth h [] = h.H [] := by simp [mth]
theorem mth_single (h : HashFn) (x : Bytes) : mth h [x] = leafHash h x := by simp [mth]

theorem mth_node (h : HashFn) (l : List Bytes) (hl : 2 ≤ l.length) :
    mth h l = nodeHash h (mth h (l.take (split l.length))) (mth h (l.drop (split l.length))) := by
  match l, hl with
  | x :: y :: t, _ => rw [mth]; rfl

theorem mth_length (h : HashFn) (l : List Bytes) : (mth h l).length = 32 := by
  match l with
  | [] => simp [mth_nil, h.len32]
  | [x] => simp [mth_single, leafHash, h.len32]
  | x :: y :: t => rw [mth_node h _ (by simp)]; simp [nodeHash, h.len32]

/-! ### Collision lemmas -/

theorem H_eq (h : HashFn) {a b : Bytes} (e : h.H a = h.H b) : a = b ∨ Collision h := by
  by_cases hab : a = b
  · exact .inl hab
  · exact .inr ⟨a, b, hab, e⟩

/-- Equal node hashes: the left halves have the given lengths, so the halves agree. -/
theorem node_inj (h : HashFn) {a b c d : Bytes} (hl : a.length = c.length)
    (e : nodeHash h a b = nodeHash h c d) : (a = c ∧ b = d) ∨ Collision h := by
  rcases H_eq h e with e | e
  · simp only [List.cons.injEq, true_and] at e
    exact .inl (List.append_inj e hl)
  · exact .inr e

/-- The Merkle Tree Hash is injective unless the hash function has a collision, across lists of
    any lengths: the empty tree, leaves and nodes hash distinct preimages. -/
theorem mth_inj (h : HashFn) : ∀ (a b : List Bytes), mth h a = mth h b → a = b ∨ Collision h := by
  intro a b
  induction hn : a.length + b.length using Nat.strongRecOn generalizing a b with
  | _ n ih =>
    intro e
    match a, b with
    | [], [] => exact .inl rfl
    | [], [y] =>
      simp only [mth_nil, mth_single, leafHash] at e; exact .inr ⟨_, _, by simp, e⟩
    | [x], [] =>
      simp only [mth_nil, mth_single, leafHash] at e; exact .inr ⟨_, _, by simp, e⟩
    | [x], [y] =>
      rcases H_eq h (by simpa only [mth_single, leafHash] using e) with e | e
      · simp only [List.cons.injEq, true_and] at e; exact .inl (by simp [e])
      · exact .inr e
    | [], y1 :: y2 :: ys =>
      rw [mth_nil, mth_node h (y1 :: y2 :: ys) (by simp), nodeHash] at e
      exact .inr ⟨_, _, by simp, e⟩
    | x1 :: x2 :: xs, [] =>
      rw [mth_nil, mth_node h (x1 :: x2 :: xs) (by simp), nodeHash] at e
      exact .inr ⟨_, _, by simp, e⟩
    | [x], y1 :: y2 :: ys =>
      rw [mth_single, mth_node h (y1 :: y2 :: ys) (by simp), nodeHash, leafHash] at e
      exact .inr ⟨_, _, by simp, e⟩
    | x1 :: x2 :: xs, [y] =>
      rw [mth_single, mth_node h (x1 :: x2 :: xs) (by simp), nodeHash, leafHash] at e
      exact .inr ⟨_, _, by simp, e⟩
    | x1 :: x2 :: xs, y1 :: y2 :: ys =>
      rw [mth_node h (x1 :: x2 :: xs) (by simp), mth_node h (y1 :: y2 :: ys) (by simp)] at e
      rcases node_inj h (by simp only [mth_length]) e with ⟨e1, e2⟩ | c
      · have ha := split_lt (n := (x1 :: x2 :: xs).length) (by simp)
        have hb := split_lt (n := (y1 :: y2 :: ys).length) (by simp)
        have ha0 := split_pos (x1 :: x2 :: xs).length
        have hb0 := split_pos (y1 :: y2 :: ys).length
        simp only [List.length_cons] at ha hb ha0 hb0 hn
        rcases ih _ (by simp only [List.length_take, List.length_cons]; omega) _ _ rfl e1 with t | c
        · rcases ih _ (by simp only [List.length_drop, List.length_cons]; omega) _ _ rfl e2 with d | c
          · refine .inl ?_
            rw [← List.take_append_drop (split (x1 :: x2 :: xs).length) (x1 :: x2 :: xs),
              ← List.take_append_drop (split (y1 :: y2 :: ys).length) (y1 :: y2 :: ys), t, d]
          · exact .inr c
        · exact .inr c
      · exact .inr c

/-! ### Aligned windows

A node of an RFC 9162 tree at level `k` with index `j` covers the leaves
`[j·2^k, (j+1)·2^k)`, cut at the end of the list. Where only the left half exists, the node is the
left child itself ("promotion"). These lemmas are what the iterative verifiers rely on. -/

/-- Leaves under the node at level `k`, index `j`. -/
def win (l : List Bytes) (k j : Nat) : List Bytes := (l.drop (j * 2 ^ k)).take (2 ^ k)

/-- Hash of the node at level `k`, index `j`. -/
def T (h : HashFn) (l : List Bytes) (k j : Nat) : Bytes := mth h (win l k j)

theorem T_length (h : HashFn) (l : List Bytes) (k j : Nat) : (T h l k j).length = 32 :=
  mth_length h _

theorem win_length (l : List Bytes) (k j : Nat) :
    (win l k j).length = min (2 ^ k) (l.length - j * 2 ^ k) := by
  simp [win, List.length_take, List.length_drop]

/-- A node with both children present is the hash of its children. -/
theorem T_node (h : HashFn) (l : List Bytes) (k j : Nat) (hlt : (2 * j + 1) * 2 ^ k < l.length) :
    T h l (k + 1) j = nodeHash h (T h l k (2 * j)) (T h l k (2 * j + 1)) := by
  have hp := Nat.one_le_two_pow (n := k)
  have e1 : j * 2 ^ (k + 1) = 2 * j * 2 ^ k := by grind
  have e2 : (2 * j + 1) * 2 ^ k = 2 * j * 2 ^ k + 2 ^ k := by grind
  have e3 : 2 ^ (k + 1) = 2 ^ k + 2 ^ k := by grind
  have hw := win_length l (k + 1) j
  have hlen1 : 2 ^ k < (win l (k + 1) j).length := by rw [hw]; omega
  have hlen2 : (win l (k + 1) j).length ≤ 2 ^ (k + 1) := by rw [hw]; omega
  unfold T
  rw [mth_node h _ (by omega), split_eq hlen1 hlen2]
  congr 2
  · simp only [win, List.take_take, e1]
    congr 1; omega
  · simp only [win, List.drop_take, List.drop_drop, e1, e2]
    congr 1
    omega

/-- Promotion: a node whose right part is empty at every level from `k` to `k+s` has the hash
    of its leftmost descendant at level `k`. -/
theorem T_promote (h : HashFn) (l : List Bytes) (k s x : Nat)
    (hge : l.length ≤ (x * 2 ^ s + 1) * 2 ^ k) :
    T h l (k + s) x = T h l k (x * 2 ^ s) := by
  have e1 : x * 2 ^ (k + s) = x * 2 ^ s * 2 ^ k := by grind
  have e2 : (x * 2 ^ s + 1) * 2 ^ k = x * 2 ^ s * 2 ^ k + 2 ^ k := by grind
  have hle : 2 ^ k ≤ 2 ^ (k + s) := Nat.pow_le_pow_right (by decide) (by omega)
  unfold T win
  rw [e1, List.take_of_length_le (by simp [List.length_drop]; omega),
    List.take_of_length_le (by simp [List.length_drop]; omega)]

/-- The window that covers the whole list is the tree itself. -/
theorem T_top (h : HashFn) (l : List Bytes) (k : Nat) (hle : l.length ≤ 2 ^ k) :
    T h l k 0 = mth h l := by
  simp [T, win, List.take_of_length_le hle]

/-- The last leaf of a list of length `L ≥ 1` lies in node `(L-1)/2^k` at level `k`. -/
theorem last_node_bounds (L k : Nat) (hL : 1 ≤ L) :
    (L - 1) / 2 ^ k * 2 ^ k ≤ L - 1 ∧ L ≤ ((L - 1) / 2 ^ k + 1) * 2 ^ k := by
  have hp : 0 < 2 ^ k := Nat.pow_pos (by decide)
  refine ⟨Nat.div_mul_le_self _ _, ?_⟩
  have := Nat.lt_mul_div_succ (L - 1) hp
  rw [Nat.mul_comm] at this
  omega

/-- Equal prefixes extended by equal windows. -/
theorem take_extend (l₁ l₂ : List Bytes) (k j : Nat)
    (hp : l₁.take (j * 2 ^ k) = l₂.take (j * 2 ^ k)) (hw : win l₁ k j = win l₂ k j) :
    l₁.take ((j + 1) * 2 ^ k) = l₂.take ((j + 1) * 2 ^ k) := by
  rw [show (j + 1) * 2 ^ k = j * 2 ^ k + 2 ^ k by grind, List.take_add, List.take_add, hp]
  simp only [win] at hw
  rw [hw]

/-- Equal prefix up to the last old leaf's node, and that node's window equal: a prefix. -/
theorem prefix_of_last (l₁ l₂ : List Bytes) (k j : Nat)
    (hp : l₁.take (j * 2 ^ k) = l₂.take (j * 2 ^ k)) (hw : win l₁ k j = win l₂ k j)
    (hlen : l₁.length ≤ (j + 1) * 2 ^ k) : l₁ <+: l₂ := by
  have := take_extend l₁ l₂ k j hp hw
  rw [List.take_of_length_le hlen] at this
  rw [this]
  exact List.take_prefix _ _

/-- Equal node hashes give equal windows (or a collision). -/
theorem win_eq_of_T (h : HashFn) (l₁ l₂ : List Bytes) (k j : Nat)
    (e : T h l₁ k j = T h l₂ k j) : win l₁ k j = win l₂ k j ∨ Collision h :=
  mth_inj h _ _ e

/-- Node hashes agree, using the right halves' lengths. -/
theorem node_inj' (h : HashFn) {a b c d : Bytes} (hr : b.length = d.length)
    (e : nodeHash h a b = nodeHash h c d) : (a = c ∧ b = d) ∨ Collision h := by
  rcases H_eq h e with e | e
  · simp only [List.cons.injEq, true_and] at e
    exact .inl (List.append_inj' e hr)
  · exact .inr e

/-! ### RFC 9162 consistency verification (as in the design doc) -/

/-- Shift both right until `fn` is odd or zero. -/
def shiftUntilOdd : Nat → Nat → Nat × Nat
  | 0, sn => (0, sn)
  | fn + 1, sn => if (fn + 1) % 2 = 1 then (fn + 1, sn) else shiftUntilOdd ((fn + 1) / 2) (sn / 2)
termination_by fn _ => fn
decreasing_by all_goals (simp_wf; omega)

/-- Shift both right while `fn` is odd. -/
def shiftWhileOdd : Nat → Nat → Nat × Nat
  | 0, sn => (0, sn)
  | fn + 1, sn => if (fn + 1) % 2 = 1 then shiftWhileOdd ((fn + 1) / 2) (sn / 2) else (fn + 1, sn)
termination_by fn _ => fn
decreasing_by all_goals (simp_wf; omega)

def isPow2 (n : Nat) : Bool := n != 0 && (n &&& (n - 1)) == 0

/-- Consistency verification, RFC 9162 §2.1.4.2. -/
def verifyConsistency (h : HashFn) (m n : Nat) (oldRoot newRoot : Bytes)
    (proof : List Bytes) : Bool :=
  if n < m then false
  else if m = n then proof.isEmpty && oldRoot == newRoot
  else if m = 0 then proof.isEmpty
  else
    let rec go (fn sn : Nat) (fr sr : Bytes) : List Bytes → Bool
      | [] => sn == 0 && fr == oldRoot && sr == newRoot
      | c :: rest =>
        if sn = 0 then false
        else if fn % 2 = 1 ∨ fn = sn then
          let (fn', sn') := if fn % 2 = 1 then (fn, sn) else shiftUntilOdd fn sn
          go (fn' / 2) (sn' / 2) (nodeHash h c fr) (nodeHash h c sr) rest
        else go (fn / 2) (sn / 2) fr (nodeHash h sr c) rest
    match (if isPow2 m then oldRoot :: proof else proof) with
    | [] => false
    | c₀ :: cs =>
      let (fn₀, sn₀) := shiftWhileOdd (m - 1) (n - 1)
      go fn₀ sn₀ c₀ c₀ cs

/-- `shiftWhileOdd` divides both arguments by the same power of two. -/
theorem shiftWhileOdd_spec : ∀ a b : Nat, ∃ s, shiftWhileOdd a b = (a / 2 ^ s, b / 2 ^ s) := by
  intro a
  induction a using Nat.strongRecOn with
  | _ a ih =>
    intro b
    match a with
    | 0 => exact ⟨0, by simp [shiftWhileOdd]⟩
    | a + 1 =>
      by_cases hodd : (a + 1) % 2 = 1
      · obtain ⟨s, hs⟩ := ih ((a + 1) / 2) (by omega) (b / 2)
        refine ⟨s + 1, ?_⟩
        rw [shiftWhileOdd, if_pos hodd, hs, Nat.div_div_eq_div_mul, Nat.div_div_eq_div_mul,
          Nat.pow_succ, Nat.mul_comm (2 ^ s) 2]
      · exact ⟨0, by rw [shiftWhileOdd, if_neg hodd]; simp⟩

/-- From equal nonzero arguments, `shiftUntilOdd` strips the factors of two. -/
theorem shiftUntilOdd_spec : ∀ f : Nat, f ≠ 0 →
    ∃ s x, shiftUntilOdd f f = (x, x) ∧ x % 2 = 1 ∧ f = x * 2 ^ s := by
  intro f
  induction f using Nat.strongRecOn with
  | _ f ih =>
    intro hf
    match f, hf with
    | g + 1, _ =>
      by_cases hodd : (g + 1) % 2 = 1
      · exact ⟨0, g + 1, by rw [shiftUntilOdd, if_pos hodd], hodd, by simp⟩
      · obtain ⟨s, x, hs, hx, hfx⟩ := ih ((g + 1) / 2) (by omega) (by omega)
        refine ⟨s + 1, x, by rw [shiftUntilOdd, if_neg hodd, hs], hx, ?_⟩
        rw [Nat.pow_succ, ← Nat.mul_assoc, ← hfx]
        omega

/-! ### Inclusion proofs (design doc §2; definitions only, theorems not yet proved) -/

/-- PATH(m, D[n]), RFC 9162 §2.1.3.1. -/
def inclusionProof (h : HashFn) (i : Nat) (l : List Bytes) : List Bytes :=
  if _hl : l.length ≤ 1 then []
  else
    let k := split l.length
    if i < k then inclusionProof h i (l.take k) ++ [mth h (l.drop k)]
    else inclusionProof h (i - k) (l.drop k) ++ [mth h (l.take k)]
termination_by l.length
decreasing_by
  all_goals
    simp only [List.length_take, List.length_drop]
    have := split_pos l.length
    have := split_lt (n := l.length) (by omega)
    omega

/-- Inclusion verification, RFC 9162 §2.1.3.2. -/
def verifyInclusion (h : HashFn) (index size : Nat) (leaf root : Bytes)
    (path : List Bytes) : Bool :=
  let rec go (fn sn : Nat) (r : Bytes) : List Bytes → Bool
    | [] => sn == 0 && r == root
    | p :: ps =>
      if sn = 0 then false
      else if fn % 2 = 1 ∨ fn = sn then
        let (fn', sn') := if fn % 2 = 1 then (fn, sn) else shiftUntilOdd fn sn
        go (fn' / 2) (sn' / 2) (nodeHash h p r) ps
      else go (fn / 2) (sn / 2) (nodeHash h r p) ps
  index < size && go index (size - 1) leaf path

/-! ### Proof generation (RFC 9162 §2.1.4.1), for testing and for `consistency_complete` -/

/-- SUBPROOF(m, D[n], b). -/
def subproof (h : HashFn) (m : Nat) (l : List Bytes) (b : Bool) : List Bytes :=
  if m = l.length then (if b then [] else [mth h l])
  else if _hl : l.length ≤ 1 then []
  else
    let k := split l.length
    if m ≤ k then subproof h m (l.take k) b ++ [mth h (l.drop k)]
    else subproof h (m - k) (l.drop k) false ++ [mth h (l.take k)]
termination_by l.length
decreasing_by
  all_goals
    simp only [List.length_take, List.length_drop]
    have := split_pos l.length
    have := split_lt (n := l.length) (by omega)
    omega

def consistencyProof (h : HashFn) (m : Nat) (l : List Bytes) : List Bytes :=
  if m = 0 ∨ l.length ≤ m then [] else subproof h m l true

/-! ### Soundness of consistency verification

Read a successful run of `go` backwards. At level `k` the loop's indices are `fn = (m-1)/2^k` and
`sn = (n-1)/2^k`, the nodes holding the last old and the last new leaf. Unless there is a
collision, each proof hash the loop combines on the left is the true left sibling in *both* trees,
`fr` and `sr` are the true nodes `fn` of the old and the new tree, and the two lists agree on
every leaf before node `fn`. At the bottom `fr = sr`, which makes node `fn` equal in both trees,
and then the old list is a prefix of the new one. -/

/-- Shared step for the branch that hashes a left sibling into both accumulators. The step runs
    at level `K ≥ k`, at odd index `x` with `x·2^K = fn·2^k` (after promotions when `K > k`). -/
theorem odd_step (h : HashFn) (l₁ l₂ : List Bytes) (hmn : l₁.length ≤ l₂.length)
    (k fn K x : Nat) (c fr sr : Bytes) (hK : k ≤ K)
    (hx : x % 2 = 1) (hxK : x * 2 ^ K = fn * 2 ^ k) (hx1 : x * 2 ^ K < l₁.length)
    (hlast : l₁.length ≤ (fn + 1) * 2 ^ k)
    (hP1 : T h l₁ K x = T h l₁ k fn) (hP2 : T h l₂ K x = T h l₂ k fn)
    (hlen : sr.length = 32 ∨ fr = sr)
    (ihr : (l₁ <+: l₂ ∨ Collision h) ∨
      (l₁.take (x / 2 * 2 ^ (K + 1)) = l₂.take (x / 2 * 2 ^ (K + 1)) ∧
        nodeHash h c fr = T h l₁ (K + 1) (x / 2) ∧ nodeHash h c sr = T h l₂ (K + 1) (x / 2))) :
    (l₁ <+: l₂ ∨ Collision h) ∨
      (l₁.take (fn * 2 ^ k) = l₂.take (fn * 2 ^ k) ∧ fr = T h l₁ k fn ∧ sr = T h l₂ k fn) := by
  rcases ihr with g | ⟨hpre, e1, e2⟩
  · exact .inl g
  have hj : (2 * (x / 2) + 1) * 2 ^ K = x * 2 ^ K := by
    rw [show 2 * (x / 2) + 1 = x by omega]
  rw [T_node h l₁ K (x / 2) (by omega), show 2 * (x / 2) + 1 = x by omega,
    show 2 * (x / 2) = x - 1 by omega] at e1
  rw [T_node h l₂ K (x / 2) (by omega), show 2 * (x / 2) + 1 = x by omega,
    show 2 * (x / 2) = x - 1 by omega] at e2
  have hpre' : l₁.take ((x - 1) * 2 ^ K) = l₂.take ((x - 1) * 2 ^ K) := by
    rw [show (x - 1) * 2 ^ K = x / 2 * 2 ^ (K + 1) by
      rw [Nat.pow_succ, show x - 1 = 2 * (x / 2) by omega]; grind]
    exact hpre
  -- the sibling windows agree, so the prefix extends to node x
  have extend : win l₁ K (x - 1) = win l₂ K (x - 1) →
      l₁.take (fn * 2 ^ k) = l₂.take (fn * 2 ^ k) := fun hw => by
    have := take_extend l₁ l₂ K (x - 1) hpre' hw
    rwa [show x - 1 + 1 = x by omega, hxK] at this
  rcases hlen with hs32 | hfs
  · rcases node_inj' h (by rw [hs32, T_length]) e2 with ⟨ec2, es⟩ | col
    · rcases node_inj h (by rw [ec2, T_length, T_length]) e1 with ⟨ec1, ef⟩ | col
      · rcases win_eq_of_T h l₁ l₂ K (x - 1) (ec1.symm.trans ec2) with hw | col
        · exact .inr ⟨extend hw, ef.trans hP1, es.trans hP2⟩
        · exact .inl (.inr col)
      · exact .inl (.inr col)
    · exact .inl (.inr col)
  · -- fr = sr: both trees' nodes hash to the same value, so node x agrees too
    subst hfs
    rcases node_inj h (by rw [T_length, T_length]) (e1.symm.trans e2) with ⟨es, ex⟩ | col
    · rcases win_eq_of_T h l₁ l₂ K (x - 1) es with hw | col
      · rcases win_eq_of_T h l₁ l₂ K x ex with hwx | col
        · have hpx : l₁.take (x * 2 ^ K) = l₂.take (x * 2 ^ K) := by rw [hxK]; exact extend hw
          have hpow : 2 ^ k ≤ 2 ^ K := Nat.pow_le_pow_right (by decide) hK
          refine .inl (.inl (prefix_of_last l₁ l₂ K x hpx hwx ?_))
          rw [Nat.add_mul, Nat.one_mul, hxK]; rw [Nat.add_mul, Nat.one_mul] at hlast; omega
        · exact .inl (.inr col)
      · exact .inl (.inr col)
    · exact .inl (.inr col)

/-- The loop's backward invariant. -/
theorem go_sound (h : HashFn) (l₁ l₂ : List Bytes) (h1 : 1 ≤ l₁.length)
    (hmn : l₁.length ≤ l₂.length) :
    ∀ (ps : List Bytes) (k fn sn : Nat) (fr sr : Bytes),
      fn = (l₁.length - 1) / 2 ^ k → sn = (l₂.length - 1) / 2 ^ k →
      (sr.length = 32 ∨ fr = sr) →
      verifyConsistency.go h (mth h l₁) (mth h l₂) fn sn fr sr ps = true →
      (l₁ <+: l₂ ∨ Collision h) ∨
        (l₁.take (fn * 2 ^ k) = l₂.take (fn * 2 ^ k) ∧ fr = T h l₁ k fn ∧ sr = T h l₂ k fn) := by
  intro ps
  induction ps with
  | nil =>
    intro k fn sn fr sr hf hs _ hv
    simp only [verifyConsistency.go, Bool.and_eq_true, beq_iff_eq] at hv
    obtain ⟨⟨hs0, hfr⟩, hsr⟩ := hv
    have hb := (last_node_bounds l₂.length k (by omega)).2
    rw [← hs, hs0, Nat.zero_add, Nat.one_mul] at hb
    have hf0 : fn = 0 := by
      have : fn ≤ sn := by rw [hf, hs]; exact Nat.div_le_div_right (by omega)
      omega
    subst hf0
    refine .inr ⟨by simp, ?_, ?_⟩
    · rw [hfr, T_top h l₁ k (by omega)]
    · rw [hsr, T_top h l₂ k hb]
  | cons c rest ih =>
    intro k fn sn fr sr hf hs hlen hv
    have hp : 0 < 2 ^ k := Nat.pow_pos (by decide)
    have ⟨hf1, hf2⟩ := last_node_bounds l₁.length k h1
    have ⟨hs1, hs2⟩ := last_node_bounds l₂.length k (by omega)
    rw [← hf] at hf1 hf2
    rw [← hs] at hs1 hs2
    have hnext : ∀ q, q = (l₁.length - 1) / 2 ^ k → q / 2 = (l₁.length - 1) / 2 ^ (k + 1) :=
      fun q hq => by rw [hq, Nat.div_div_eq_div_mul, Nat.pow_succ]
    have hnext2 : ∀ q, q = (l₂.length - 1) / 2 ^ k → q / 2 = (l₂.length - 1) / 2 ^ (k + 1) :=
      fun q hq => by rw [hq, Nat.div_div_eq_div_mul, Nat.pow_succ]
    have h32 : ∀ a b, (nodeHash h a b).length = 32 := fun a b => h.len32 _
    rw [verifyConsistency.go] at hv
    by_cases hs0 : sn = 0
    · simp [hs0] at hv
    rw [if_neg hs0] at hv
    by_cases hodd : fn % 2 = 1
    · -- left sibling at this level
      rw [if_pos (.inl hodd), if_pos hodd] at hv
      have ihr := ih (k + 1) (fn / 2) (sn / 2) _ _ (hnext fn hf) (hnext2 sn hs) (.inl (h32 _ _)) hv
      exact odd_step h l₁ l₂ hmn k fn k fn c fr sr (Nat.le_refl _) hodd rfl (by omega) hf2 rfl rfl
        hlen ihr
    by_cases heq : fn = sn
    · -- last node in both trees: promote until odd, then a left sibling
      rw [if_pos (.inr heq), if_neg hodd, ← heq] at hv
      obtain ⟨s, x, hsu, hx, hfx⟩ := shiftUntilOdd_spec fn (by omega)
      rw [hsu] at hv
      have hxdiv : x = fn / 2 ^ s := by
        rw [hfx, Nat.mul_div_cancel _ (Nat.pow_pos (by decide))]
      have hlev1 : x / 2 = (l₁.length - 1) / 2 ^ (k + s + 1) := by
        rw [hxdiv, hf, Nat.div_div_eq_div_mul, Nat.div_div_eq_div_mul, Nat.pow_succ, Nat.pow_add,
          Nat.mul_assoc]
      have hlev2 : x / 2 = (l₂.length - 1) / 2 ^ (k + s + 1) := by
        rw [hxdiv, heq, hs, Nat.div_div_eq_div_mul, Nat.div_div_eq_div_mul, Nat.pow_succ,
          Nat.pow_add, Nat.mul_assoc]
      have ihr := ih (k + s + 1) (x / 2) (x / 2) _ _ hlev1 hlev2 (.inl (h32 _ _)) hv
      have hxK : x * 2 ^ (k + s) = fn * 2 ^ k := by rw [hfx]; grind
      have hP1 : T h l₁ (k + s) x = T h l₁ k fn := by
        rw [T_promote h l₁ k s x (by rw [← hfx]; exact hf2), ← hfx]
      have hP2 : T h l₂ (k + s) x = T h l₂ k fn := by
        rw [T_promote h l₂ k s x (by rw [← hfx, heq]; exact hs2), ← hfx]
      exact odd_step h l₁ l₂ hmn k fn (k + s) x c fr sr (by omega) hx hxK (by omega) hf2 hP1 hP2
        hlen ihr
    · -- old tree's node is promoted; the new tree gets a right sibling
      rw [if_neg (by omega)] at hv
      have hlt : fn < sn := by
        have : fn ≤ sn := by rw [hf, hs]; exact Nat.div_le_div_right (by omega)
        omega
      rcases ih (k + 1) (fn / 2) (sn / 2) _ _ (hnext fn hf) (hnext2 sn hs) (.inl (h32 _ _)) hv
        with g | ⟨hpre, ef, es⟩
      · exact .inl g
      have hfe : fn / 2 * 2 ^ (k + 1) = fn * 2 ^ k := by
        rw [Nat.pow_succ, show fn = 2 * (fn / 2) by omega]; grind
      rw [hfe] at hpre
      rw [show k + 1 = k + 1 from rfl, T_promote h l₁ k 1 (fn / 2) (by
        rw [Nat.pow_one, show fn / 2 * 2 = fn by omega]; exact hf2),
        Nat.pow_one, show fn / 2 * 2 = fn by omega] at ef
      have hsib : (2 * (fn / 2) + 1) * 2 ^ k < l₂.length := by
        rw [show 2 * (fn / 2) + 1 = fn + 1 by omega]
        have : (fn + 1) * 2 ^ k ≤ sn * 2 ^ k := Nat.mul_le_mul_right _ hlt
        omega
      rw [T_node h l₂ k (fn / 2) hsib, show 2 * (fn / 2) = fn by omega] at es
      have hsr32 : sr.length = (T h l₂ k fn).length := by
        rw [T_length]
        rcases hlen with h32' | hfs
        · exact h32'
        · rw [← hfs, ef, T_length]
      rcases node_inj h hsr32 es with ⟨es', _⟩ | col
      · exact .inr ⟨hpre, ef, es'⟩
      · exact .inl (.inr col)

/-- **consistency_sound** (design doc §2): a consistency proof that verifies from the old tree's
    root to the new tree's root shows the old list is a prefix of the new one, unless the hash
    function has a collision. Holds for arbitrary proof hashes, of any length. -/
theorem consistency_sound (h : HashFn) (l₁ l₂ p : List Bytes)
    (hle : l₁.length ≤ l₂.length)
    (hv : verifyConsistency h l₁.length l₂.length (mth h l₁) (mth h l₂) p = true) :
    l₁ <+: l₂ ∨ Collision h := by
  unfold verifyConsistency at hv
  by_cases hlt : l₂.length < l₁.length
  · omega
  rw [if_neg hlt] at hv
  by_cases heq : l₁.length = l₂.length
  · rw [if_pos heq] at hv
    simp only [Bool.and_eq_true, beq_iff_eq] at hv
    rcases mth_inj h _ _ hv.2 with e | c
    · exact .inl (e ▸ List.prefix_refl _)
    · exact .inr c
  rw [if_neg heq] at hv
  by_cases h0 : l₁.length = 0
  · exact .inl (by rw [List.length_eq_zero_iff.mp h0]; exact List.nil_prefix)
  rw [if_neg h0] at hv
  generalize (if isPow2 l₁.length = true then mth h l₁ :: p else p) = q at hv
  match q, hv with
  | [], hv => simp at hv
  | c₀ :: cs, hv =>
    obtain ⟨s, hs⟩ := shiftWhileOdd_spec (l₁.length - 1) (l₂.length - 1)
    simp only [hs] at hv
    rcases go_sound h l₁ l₂ (by omega) hle cs s _ _ c₀ c₀ rfl rfl (.inr rfl) hv
      with g | ⟨hpre, e1, e2⟩
    · exact g
    · rcases win_eq_of_T h l₁ l₂ s _ (e1.symm.trans e2) with hw | c
      · exact .inl (prefix_of_last l₁ l₂ s _ hpre hw (last_node_bounds _ s (by omega)).2)
      · exact .inr c

/-- **receipt_binding** (design doc §2): every leaf a receipt or checkpoint committed to stays at
    its index in any later tree proven consistent with it. -/
theorem receipt_binding (h : HashFn) (l₁ l₂ p : List Bytes) (i : Nat) (hi : i < l₁.length)
    (hle : l₁.length ≤ l₂.length)
    (hv : verifyConsistency h l₁.length l₂.length (mth h l₁) (mth h l₂) p = true) :
    l₂[i]? = l₁[i]? ∨ Collision h := by
  rcases consistency_sound h l₁ l₂ p hle hv with hp | c
  · obtain ⟨t, rfl⟩ := hp
    exact .inl (by rw [List.getElem?_append_left hi])
  · exact .inr c

end Vesdb
