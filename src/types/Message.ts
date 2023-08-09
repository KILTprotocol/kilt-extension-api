import type { ICredential, ICredentialPresentation, IAttestation, CTypeHash, DidResourceUri, DidUri, IDelegationNode, PartialClaim, ICType } from '@kiltprotocol/types'
import type { IQuoteAgreement, IQuoteAttesterSigned } from './Quote'

/**
 * All possible message types which are defined in the KILT Credential API (Spec version 3.2)
 * https://github.com/KILTprotocol/spec-ext-credential-api
 */
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
 * Error messages signal unintentional programming errors which happened during
 * the processing of the incoming messages or when constructing a response message.
 */
export interface IError extends IMessageBodyBase {
  content: {
    /** Optional machine-readable type of the error. */
    name?: string
    /** Optional human-readable description of the error. */
    message?: string
  }
  type: 'error'
}

/**
 * Rejection messages signal the intentional cancelling of an individual step in the flow.
 */
export interface IReject extends IMessageBodyBase {
  content: {
    /** Optional machine-readable type of the rejection. */
    name?: string
    /** Optional human-readable description of the rejection. */
    message?: string
  }
  type: 'reject'
}


/**
 * An attester utilizes the message to propose a claim. The purpose of the extension is to enable
 * the user to authorize and endorse the claims prepared by the attester.
 */
export interface ISubmitTerms extends IMessageBodyBase {
  content: ITerms
  type: 'submit-terms'
}


/**
 * The content of the [IRequestAttestation] message.
 */
export interface IRequestAttestationContent {
  credential: ICredential
  quote?: IQuoteAgreement
}

/**
 * The extension only sends the request with active consent of the user. This is the first step
 * where the user’s DID is revealed to the dApp.
 */
export interface IRequestAttestation extends IMessageBodyBase {
  content: IRequestAttestationContent
  type: 'request-attestation'
}


/**
 * The content of the [IRequestPayment] message.
 */
export interface IRequestPaymentContent {
  // Same as the `rootHash` value of the `'request-attestation'` message */
  claimHash: string
}

/**
 * An attester can send this message if it wants the user to transfer payment in KILT Coins by themselves without interrupting the flow.
 */
export interface IRequestPayment extends IMessageBodyBase {
  content: IRequestPaymentContent
  type: 'request-payment'
}


/**
 * The content of the [ISubmitAttestation] message.
 */
export interface ISubmitAttestationContent {
  attestation: IAttestation
}

/**
 * The attester sends the valid credential to the extension.
 */
export interface ISubmitAttestation extends IMessageBodyBase {
  content: ISubmitAttestationContent
  type: 'submit-attestation'
}


/**
 * If the attester does not approve the attestation request, the extension receives the [IRejectAttestation] message.
 */
export interface IRejectAttestation extends IMessageBodyBase {
  content: ICredential['rootHash']
  type: 'reject-attestation'
}




/**
 * The content of the [ISubmitTerms] message.
 */
export interface ITerms {
  claim: PartialClaim
  // optional array of credentials of the attester
  legitimations: ICredential[]
  // optional ID of the DelegationNode of the attester
  delegationId?: IDelegationNode['id']
  // Optional attester-signed binding
  quote?: IQuoteAttesterSigned
  // CTypes for the proposed credential. In most cases this will be just one, but in the case of nested ctypes, this can be multiple.
  cTypes?: ICType[]
}


/** Message to submit credentials from the extension or dapp.*/
export interface ISubmitCredential extends IMessageBodyBase {
  content: ICredentialPresentation[]
  type: 'submit-credential'
}

/**
 * The content of the [IRequestCredential] message.
 */
export interface IRequestCredentialContent {
  cTypes: Array<{
    cTypeHash: CTypeHash
    trustedAttesters?: DidUri[]
    requiredProperties?: string[]
  }>
  challenge?: string
}
export interface IRequestCredential extends IMessageBodyBase {
  content: IRequestCredentialContent
  type: 'request-credential'
}


/**
 * The content of the [IConfirmPayment] message.
 */
export interface IConfirmPaymentContent {
  // Same as the `rootHash` value of the `'request-attestation'` message
  claimHash: string
  // Hash of the payment transaction */
  txHash: string
  // hash of the block which includes the payment transaction
  blockHash: string
}


/**
 * After the user has authorized the payment and it has been transferred,
 * the extension confirms the transfer to the attester by sending the [IConfirmPayment] message.
 */
export interface IConfirmPayment extends IMessageBodyBase {
  content: IConfirmPaymentContent
  type: 'confirm-payment'
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
