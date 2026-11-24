package client

import (
	"io"

	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
)

// TLS alert levels.
const (
	alertLevelWarning uint8 = 1
	alertLevelFatal   uint8 = 2
)

// TLS alert descriptions.
const (
	alertCloseNotify             uint8 = 0
	alertUnexpectedMessage       uint8 = 10
	alertBadRecordMAC            uint8 = 20
	alertDecryptionFailed        uint8 = 21
	alertRecordOverflow          uint8 = 22
	alertDecompressionFailure    uint8 = 30
	alertHandshakeFailure        uint8 = 40
	alertNoCertificate           uint8 = 41
	alertBadCertificate          uint8 = 42
	alertUnsupportedCertificate  uint8 = 43
	alertCertificateRevoked      uint8 = 44
	alertCertificateExpired      uint8 = 45
	alertCertificateUnknown      uint8 = 46
	alertIllegalParameter        uint8 = 47
	alertUnknownCA               uint8 = 48
	alertAccessDenied            uint8 = 49
	alertDecodeError             uint8 = 50
	alertDecryptError            uint8 = 51
	alertExportRestriction       uint8 = 60
	alertProtocolVersion         uint8 = 70
	alertInsufficientSecurity    uint8 = 71
	alertInternalError           uint8 = 80
	alertInappropriateFallback   uint8 = 86
	alertUserCanceled            uint8 = 90
	alertNoRenegotiation         uint8 = 100
	alertMissingExtension        uint8 = 109
	alertUnsupportedExtension    uint8 = 110
	alertCertificateUnobtainable uint8 = 111
	alertUnrecognizedName        uint8 = 112
	alertBadCertificateStatus    uint8 = 113
	alertBadCertificateHashValue uint8 = 114
	alertUnknownPSKIdentity      uint8 = 115
	alertCertificateRequired     uint8 = 116
	alertNoApplicationProtocol   uint8 = 120
)

// alertDescriptionText returns the name of an alert description.
func alertDescriptionText(description uint8) (text string) {
	switch description {
	case alertCloseNotify:
		text = "close_notify"
	case alertUnexpectedMessage:
		text = "unexpected_message"
	case alertBadRecordMAC:
		text = "bad_record_mac"
	case alertDecryptionFailed:
		text = "decryption_failed"
	case alertRecordOverflow:
		text = "record_overflow"
	case alertDecompressionFailure:
		text = "decompression_failure"
	case alertHandshakeFailure:
		text = "handshake_failure"
	case alertNoCertificate:
		text = "no_certificate"
	case alertBadCertificate:
		text = "bad_certificate"
	case alertUnsupportedCertificate:
		text = "unsupported_certificate"
	case alertCertificateRevoked:
		text = "certificate_revoked"
	case alertCertificateExpired:
		text = "certificate_expired"
	case alertCertificateUnknown:
		text = "certificate_unknown"
	case alertIllegalParameter:
		text = "illegal_parameter"
	case alertUnknownCA:
		text = "unknown_ca"
	case alertAccessDenied:
		text = "access_denied"
	case alertDecodeError:
		text = "decode_error"
	case alertDecryptError:
		text = "decrypt_error"
	case alertExportRestriction:
		text = "export_restriction"
	case alertProtocolVersion:
		text = "protocol_version"
	case alertInsufficientSecurity:
		text = "insufficient_security"
	case alertInternalError:
		text = "internal_error"
	case alertInappropriateFallback:
		text = "inappropriate_fallback"
	case alertUserCanceled:
		text = "user_canceled"
	case alertNoRenegotiation:
		text = "no_renegotiation"
	case alertMissingExtension:
		text = "missing_extension"
	case alertUnsupportedExtension:
		text = "unsupported_extension"
	case alertCertificateUnobtainable:
		text = "certificate_unobtainable"
	case alertUnrecognizedName:
		text = "unrecognized_name"
	case alertBadCertificateStatus:
		text = "bad_certificate_status_response"
	case alertBadCertificateHashValue:
		text = "bad_certificate_hash_value"
	case alertUnknownPSKIdentity:
		text = "unknown_psk_identity"
	case alertCertificateRequired:
		text = "certificate_required"
	case alertNoApplicationProtocol:
		text = "no_application_protocol"
	default:
		text = "unknown_alert"
	}

	return text
}

// alertLevelText returns the name of an alert level.
func alertLevelText(level uint8) (text string) {
	switch level {
	case alertLevelWarning:
		text = "warning"
	case alertLevelFatal:
		text = "fatal"
	default:
		text = "unknown"
	}

	return text
}

// alertFromPayload converts an alert record payload into an error.
func alertFromPayload(payload []byte) (err error) {
	if len(payload) < 2 {
		return hqgoerrors.New("invalid input, alert record is truncated")
	}

	alert := &AlertError{
		Level:       payload[0],
		Description: payload[1],
	}

	if alert.Level == alertLevelWarning && alert.Description == alertCloseNotify {
		return io.EOF
	}

	return alert
}
