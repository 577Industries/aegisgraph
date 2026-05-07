/**
 * @id aegisgraph/qr-handler
 * @name AegisGraph: Code paths consuming QR-decoded bytes
 * @description Methods that accept a `Result` from a QR/barcode decoder
 *              (ZXing, Google MLKit Barcode, custom QR libs) and proceed to
 *              parse the contents. These are device-link, payment-URI, and
 *              sticker-pack-import handlers. Each result becomes an
 *              AegisGraph handler node with path_class "qr_device_link".
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @tags security
 *       external-input
 *       qr
 *       aegisgraph-sma
 */

import java

class QrResultType extends RefType {
  QrResultType() {
    // ZXing
    this.getQualifiedName() = "com.google.zxing.Result" or
    // Google MLKit
    this.getQualifiedName() = "com.google.mlkit.vision.barcode.common.Barcode" or
    this.getQualifiedName() = "com.google.mlkit.vision.barcode.Barcode" or
    // Some apps wrap the result in their own class -- match common names.
    this.getName().regexpMatch("(?i)(ScannedQr|QrResult|BarcodeResult|DecodedQrCode)")
  }
}

class QrConsumerMethod extends Method {
  QrConsumerMethod() {
    exists(Parameter p |
      p.getCallable() = this and p.getType() instanceof QrResultType
    )
  }
}

from QrConsumerMethod m, Parameter p
where p.getCallable() = m and p.getType() instanceof QrResultType
select m,
  "QR consumer '" + m.getQualifiedName() +
    "' accepts decoded barcode/QR result type '" + p.getType().getName() + "'."
