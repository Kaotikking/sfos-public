"""Isolated Kernel Cognitive Gateway function router."""
from __future__ import annotations
CLIENTS=("HAOS","ANDROID","ESP32","INTERNAL")
class GatewayDenied(ValueError):pass
class Gateway:
 def __init__(self,handlers):
  if not isinstance(handlers,dict) or set(handlers)!=set(CLIENTS) or len({id(v) for v in handlers.values()})!=len(CLIENTS) or any(not callable(v) for v in handlers.values()):raise GatewayDenied("GATEWAY_ISOLATION_DENIED")
  self._handlers=dict(handlers)
 def call(self,client,packet):
  if client not in CLIENTS or not isinstance(packet,dict) or packet.get("client")!=client:raise GatewayDenied("GATEWAY_ROUTE_DENIED")
  result=self._handlers[client](dict(packet))
  if not isinstance(result,dict):raise GatewayDenied("GATEWAY_RESULT_DENIED")
  return {"schema":"SEREIN/KernelCognitiveGatewayResponse/v1","client":client,"result":result,"isolation":"PER_CLIENT_FUNCTION","authority_effect":"NONE"}
