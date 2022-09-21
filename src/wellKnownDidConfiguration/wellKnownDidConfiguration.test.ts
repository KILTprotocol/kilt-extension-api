import {
  KeystoreSigner,
  KeyringPair,
  DidUri,
  ICredential,
  KiltKeyringPair,
} from '@kiltprotocol/sdk-js'
import { mnemonicGenerate } from '@polkadot/util-crypto'
import { VerifiableDomainLinkagePresentation } from '../types/types'
import { Keyring } from '@kiltprotocol/utils'

import { createCredential } from './wellKnownDidConfiguration'
import { generateDid, keypairs } from '../tests/utils'

describe('Well Known Did Configuration end to end', () => {
  let mnemonic: string
  let account: KeyringPair
  const origin = 'http://localhost:3000'
  let attesterSign: KeystoreSigner
  let didUri: DidUri
  let keypair
  let domainLinkageCredential: VerifiableDomainLinkagePresentation
  let credential: ICredential
  let expirationDate: string

  beforeAll(async () => {
    mnemonic = mnemonicGenerate()
    account = new Keyring().addFromMnemonic(mnemonic)
    keypair = await keypairs(account, mnemonic)
    didUri = await generateDid(account, mnemonic, authenticationSigner())
  })

  it('generate a well known did configuration credential', () => {
    expect(createCredential(attesterSign, origin, didUri)).toBeCalled()
  })
})
