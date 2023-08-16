import { DidResourceUri } from '@kiltprotocol/types'
import { PubSubSessionV2 } from '../../types'

export interface IRequestSession {
  name: string
  senderEncryptionKeyUri: DidResourceUri
  challenge: string
}

export type Session = ISession | PubSubSessionV2

interface ISession {
  encryptionKeyUri: DidResourceUri
  encryptedChallenge: string
  nonce: string
}
