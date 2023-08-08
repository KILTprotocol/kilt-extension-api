import type { ITerms } from './Terms'
import type { ICredential, ICredentialPresentation, IAttestation, CTypeHash, DidResourceUri, DidUri, IDelegationNode,PartialClaim } from '@kiltprotocol/types'
import type { IQuoteAgreement } from './Quote'


export interface IDelegationData {
  account: IDelegationNode['account']
  id: IDelegationNode['id']
  parentId: IDelegationNode['id']
  permissions: IDelegationNode['permissions']
  isPCR: boolean
}

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
  | 'reject-terms'

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

export interface IRejectTermsContent {
  claim: PartialClaim
  legitimations: ICredential[]
  delegationId?: IDelegationNode['id']
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

/**
 * - `body` - The body of the message, see [[MessageBody]].
 * - `createdAt` - The timestamp of the message construction.
 * - `sender` - The DID of the sender.
 * - `receiver` - The DID of the receiver.
 * - `messageId` - The message id.
 * - `receivedAt` - The timestamp of the message reception.
 * - `inReplyTo` - The id of the parent-message.
 * - `references` - The references or the in-reply-to of the parent-message followed by the message-id of the parent-message.
 */
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

/**
 * Everything which is part of the encrypted and protected part of the [[IMessage]].
 */
export type IEncryptedMessageContents = Omit<IMessage, 'receivedAt'>

/**
 * Removes the plaintext [[IEncryptedMessageContents]] from an [[IMessage]] and instead includes them in encrypted form.
 * This adds the following fields:
 * - `ciphertext` - The encrypted message content.
 * - `nonce` - The encryption nonce.
 * - `receiverKeyUri` - The URI of the receiver's encryption key.
 * - `senderKeyUri` - The URI of the sender's encryption key.
 */
export type IEncryptedMessage = Pick<IMessage, 'receivedAt'> & {
  receiverKeyUri: DidResourceUri
  senderKeyUri: DidResourceUri
  ciphertext: string
  nonce: string
}
