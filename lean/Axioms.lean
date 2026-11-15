import Merkle
import Store
-- Each must list only Lean's standard axioms (no `sorryAx`).
#print axioms Vesdb.consistency_sound
#print axioms Vesdb.receipt_binding
#print axioms Vesdb.mth_inj
#print axioms VesdbStore.no_fork
#print axioms VesdbStore.views_prefix
#print axioms VesdbStore.ack_durable
#print axioms VesdbStore.receipt_sound
#print axioms VesdbStore.idempotent
#print axioms VesdbStore.redaction_keeps_proofs
#print axioms VesdbStore.two_writers_take_turns
