;; CryptoVault Certification Network - Distributed ledger protocol for verifiable digital certificate issuance and management
;;
;; This protocol establishes a trustless framework for creating, validating, and transferring digital certificates
;; with comprehensive traceability and fine-grained access management capabilities

;; Master Certificate Counter
(define-data-var certificate-sequence-tracker uint u0)

;; Protocol Governor
(define-constant governance-principal tx-sender)

;; Protocol Response Status Codes

(define-constant unauthorized-certificate-interaction-code (err u306))
(define-constant governance-restricted-action-code (err u300))
(define-constant certificate-lookup-failure-code (err u301))
(define-constant certificate-already-exists-code (err u302))
(define-constant certificate-name-validation-code (err u303))
(define-constant certificate-metric-validation-code (err u304))
(define-constant unauthorized-access-attempt-code (err u305))
(define-constant certificate-viewing-restricted-code (err u307))
(define-constant certificate-metadata-validation-code (err u308))

;; Core Certificate Storage
(define-map certificate-repository
  { certificate-id: uint }
  {
    certificate-name: (string-ascii 64),
    certificate-holder: principal,
    certificate-size: uint,
    issuance-height: uint,
    certificate-metadata: (string-ascii 128),
    certificate-categories: (list 10 (string-ascii 32))
  }
)

;; Certificate Access Control Matrix
(define-map access-control-matrix
  { certificate-id: uint, accessor: principal }
  { can-access: bool }
)

;; ===== Helper Functions =====

;; Validates category formatting requirements
(define-private (is-category-valid (category (string-ascii 32)))
  (and
    (> (len category) u0)
    (< (len category) u33)
  )
)

;; Validates the complete set of categories
(define-private (validate-category-set (categories (list 10 (string-ascii 32))))
  (and
    (> (len categories) u0)
    (<= (len categories) u10)
    (is-eq (len (filter is-category-valid categories)) (len categories))
  )
)

;; Verifies if certificate exists in repository
(define-private (certificate-exists (certificate-id uint))
  (is-some (map-get? certificate-repository { certificate-id: certificate-id }))
)

;; Retrieves size value for a certificate
(define-private (get-certificate-size (certificate-id uint))
  (default-to u0
    (get certificate-size
      (map-get? certificate-repository { certificate-id: certificate-id })
    )
  )
)

;; Certificate ownership validation
(define-private (is-certificate-owner (certificate-id uint) (accessor principal))
  (match (map-get? certificate-repository { certificate-id: certificate-id })
    certificate-record (is-eq (get certificate-holder certificate-record) accessor)
    false
  )
)

;; ===== Certificate Management Functions =====

;; Transfer certificate ownership to recipient
(define-public (transfer-certificate-ownership (certificate-id uint) (recipient principal))
  (let
    (
      (certificate-record (unwrap! (map-get? certificate-repository { certificate-id: certificate-id })
        certificate-lookup-failure-code))
    )
    ;; Validate caller is current owner
    (asserts! (certificate-exists certificate-id) certificate-lookup-failure-code)
    (asserts! (is-eq (get certificate-holder certificate-record) tx-sender) unauthorized-certificate-interaction-code)

    ;; Update ownership record
    (map-set certificate-repository
      { certificate-id: certificate-id }
      (merge certificate-record { certificate-holder: recipient })
    )
    (ok true)
  )
)