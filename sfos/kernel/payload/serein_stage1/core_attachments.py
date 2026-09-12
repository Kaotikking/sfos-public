"""Inert post-Stage-1 attachment contracts; this module activates nothing."""
CORE_ORDER=("PLATFORM","ROOT","MEMORY","KNOWLEDGE","UI","AUDIO","PERSONALITY","MODULAR","CLOUD")
def contracts():
 return [{"domain":name,"identity":"SEREIN_DOMAIN_"+name,"api_version":"v1","blueprint":"REQUIRED_UNLOADED","dependencies":list(CORE_ORDER[:index]),"admission_state":"UNADMITTED","state":"INERT","activation":"OUTPOST_ONLY","api_required":True,"authority_effect":"NONE"} for index,name in enumerate(CORE_ORDER)]
