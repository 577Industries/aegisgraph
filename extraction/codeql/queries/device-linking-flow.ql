/**
 * @id aegisgraph/device-linking-flow
 * @name AegisGraph: Code paths binding a new device
 * @description Methods that handle device-linking events (Signal
 *              `LinkedDevice`, `DeviceLinkUrl`, Matrix
 *              `verification.MasterKey`, generic
 *              `addDevice/registerDevice/linkDevice` patterns). These are
 *              high-stakes auth paths and become AegisGraph control nodes
 *              in the qr_device_link / sync_state path-classes.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       crypto
 *       device-linking
 *       aegisgraph-sma
 */

import java

class DeviceLinkType extends RefType {
  DeviceLinkType() {
    this.getName().regexpMatch(
      "(?i).*(LinkedDevice|DeviceLinkUrl|ProvisioningCipher|ProvisioningUuid|" +
        "DeviceProvisioning|MasterKey|VerificationRequest|" +
        "PrimaryDevice|SecondaryDevice).*"
    )
  }
}

class DeviceLinkMethod extends Method {
  DeviceLinkMethod() {
    // By name
    this.getName().regexpMatch(
      "(?i)(addDevice|registerDevice|linkDevice|provisionDevice|verifyDevice|" +
        "unlinkDevice|deviceLink|linkedDevice|onLinkRequested).*"
    )
    or
    // By argument type
    exists(Parameter p |
      p.getCallable() = this and p.getType() instanceof DeviceLinkType
    )
  }
}

from DeviceLinkMethod m
select m,
  "Device-linking method '" + m.getQualifiedName() + "'."
