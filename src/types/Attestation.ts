import { IEncryptedMessage, IMessage } from './Message'

export interface ISubmitTermsRequest {
  message: IMessage
  encryptedMessage: IEncryptedMessage
}
