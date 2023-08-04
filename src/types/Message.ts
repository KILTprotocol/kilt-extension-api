import type { ITerms } from './Terms'
import type { ICredential, ICredentialPresentation } from './Credential'
import type { IQuoteAgreement } from './Quote'
import type { IAttestation } from './Attestation'
import type { CTypeHash } from './CType'
import type { DidUri } from './DidDocument'

export type MessageBodyType =
  | 'error'
  | 'reject'
  | 'submit-terms'
  | 'request-attestation'
  | 'request-payment'
  | 'confirm-payment'
  | 'submit-attestation'
  | 'reject-attestation'
  | 'request-credential'
  | 'submit-credential'

interface IMessageBodyBase {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  content: any
  type: MessageBodyType
}

export interface IError extends IMessageBodyBase {
  content: {
    /** Optional machine-readable type of the error. */
    name?: string
    /** Optional human-readable description of the error. */
    message?: string
  }
  type: 'error'
}

export interface IReject extends IMessageBodyBase {
  content: {
    /** Optional machine-readable type of the rejection. */
    name?: string
    /** Optional human-readable description of the rejection. */
    message?: string
  }
  type: 'reject'
}

export interface ISubmitTerms extends IMessageBodyBase {
  content: ITerms
  type: 'submit-terms'
}

export interface IRequestAttestationContent {
  credential: ICredential
  quote?: IQuoteAgreement
}

export interface IRequestAttestation extends IMessageBodyBase {
  content: IRequestAttestationContent
  type: 'request-attestation'
}

export interface IRequestPaymentContent {
  // Same as the `rootHash` value of the `'request-attestation'` message */
  claimHash: string
}

export interface IRequestPayment extends IMessageBodyBase {
  content: IRequestPaymentContent
  type: 'request-payment'
}

export interface ISubmitAttestationContent {
  attestation: IAttestation
}

export interface ISubmitAttestation extends IMessageBodyBase {
  content: ISubmitAttestationContent
  type: 'submit-attestation'
}

export interface IRejectAttestation extends IMessageBodyBase {
  content: ICredential['rootHash']
  type: 'reject-attestation'
}

export interface IRequestCredentialContent {
  cTypes: Array<{
    cTypeHash: CTypeHash
    trustedAttesters?: DidUri[]
    requiredProperties?: string[]
  }>
  challenge?: string
}

export interface ISubmitCredential extends IMessageBodyBase {
  content: ICredentialPresentation[]
  type: 'submit-credential'
}

export interface IRequestCredential extends IMessageBodyBase {
  content: IRequestCredentialContent
  type: 'request-credential'
}

export interface IConfirmPaymentContent {
  // Same as the `rootHash` value of the `'request-attestation'` message
  claimHash: string
  // Hash of the payment transaction */
  txHash: string
  // hash of the block which includes the payment transaction
  blockHash: string
}

export interface IConfirmPayment extends IMessageBodyBase {
  content: IConfirmPaymentContent
  type: 'confirm-payment'
}

export type MessageBody =
  | IError
  | IReject
  | ISubmitTerms
  | IRequestAttestation
  | IRequestPayment
  | IConfirmPayment
  | ISubmitAttestation
  | IRejectAttestation
  | IRequestCredential
  | ISubmitCredential

export interface IMessage {
  body: MessageBody
  createdAt: number
  sender: DidUri
  receiver: DidUri
  messageId?: string
  receivedAt?: number
  inReplyTo?: IMessage['messageId']
  references?: Array<IMessage['messageId']>
}
