from outpost.host_vitality import digest


def active_host(body):
    value=dict(body)
    value["schema"]="SereinOutpostHostVitalityObservation/v3"
    value["public_base"]={"repository":"Kaotikking/sfos-public","commit":"0dca6bd7a22b83b04ddf353df901d2c7ea15c294","tree":"8c56a80487f25150ffec90316a946ac89f64fb92","lock_path":"sfos/base/packages.lock","lock_sha256":"a"*64,"policy_path":"sfos/base/installer/base-policy.json","policy_sha256":"b"*64,"expected_packages":{},"observed_packages":{},"exact_diff":[],"unknowns":[],"status":"PASS"}
    value["debian"]={"release":"Debian 13","release_sha256":"c"*64,"signer_fingerprint":"d"*64,"repositories":["deb.debian.org","security.debian.org"],"installed_identity":{},"installed_packages":{},"repository_packages":{},"exact_diff":[],"pins":[],"exceptions":[],"unknowns":[],"correction_result":"NOT_REQUIRED","status":"PASS"}
    packages={"python3":"3.13.5-1"}
    value["public_base"].update(expected_packages=dict(packages),observed_packages=dict(packages))
    value["debian"].update(installed_packages=dict(packages),repository_packages=dict(packages),
                           installed_identity={"id":value["host"]["os_id"],
                                               "version_id":value["host"]["os_version_id"],
                                               "pretty_name":"Debian GNU/Linux 13 (trixie)"})
    return {**value,"evidence_digest":digest(value)}
