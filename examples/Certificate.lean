import Std
namespace TraceProof
 theorem addEq {a b c d : Int} (h1 : a = b) (h2 : c = d) :
     a + c = b + d := by
   cases h1
   cases h2
   rfl
 theorem subEq {a b c d : Int} (h1 : a = b) (h2 : c = d) :
     a - c = b - d := by
   cases h1
   cases h2
   rfl
 theorem ltTransport {x a y b : Int} (hx : x = a) (hy : y = b)
     (h : a < b) : x < y := by
   cases hx
   cases hy
   exact h
 theorem leTransport {x a y b : Int} (hx : x = a) (hy : y = b)
     (h : a ≤ b) : x ≤ y := by
   cases hx
   cases hy
   exact h
end TraceProof
set_option maxHeartbeats 50000
set_option maxRecDepth 512

theorem certificate
    (v0 : Int)
    (v1 : Int)
    (v2 : Int)
    (h0 : (v0 = (120 : Int)))
    (h1 : (v1 = (16 : Int)))
    (h2 : (v2 = (128 : Int))) : (v2 < (v0 + v1)) := by
  have s0 : (v0 = (120 : Int)) := h0
  have s1 : (v1 = (16 : Int)) := h1
  have s2 : (v2 = (128 : Int)) := h2
  have s3 : ((v0 + v1) = ((120 : Int) + (16 : Int))) := TraceProof.addEq s0 s1
  have s4 : (((120 : Int) + (16 : Int)) = (136 : Int)) := by decide
  have s5 : ((v0 + v1) = (136 : Int)) := Eq.trans s3 s4
  have s6 : ((128 : Int) < (136 : Int)) := by decide
  have s7 : (v2 < (v0 + v1)) := TraceProof.ltTransport s2 s5 s6
  exact s7

#print axioms certificate
