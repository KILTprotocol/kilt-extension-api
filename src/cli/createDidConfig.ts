#!/usr/bin/env node

import { Credential, Did, connect, disconnect } from '@kiltprotocol/sdk-js'
import { DidResourceUri, DidUri, ICredentialPresentation, SignCallback } from '@kiltprotocol/types'
import { readFile, writeFile } from 'fs/promises'
import yargs from 'yargs/yargs'
import { Keyring } from '@polkadot/keyring'

import { makeDidConfigResourceFromCredential, createCredential } from '../wellKnownDidConfiguration'
import { DidConfigResource } from '../types'

type KeyType = 'sr25519' | 'ed25519' | 'ecdsa'

async function issueCredential(
  key: string,
  did: DidUri | undefined,
  origin: string,
  seed: string,
  keyType: KeyType,
  nodeAddress: string
) {
  let didUri: DidUri
  let keyUri: DidResourceUri
  if (key.startsWith('did')) {
    const controller = Did.parse(key as DidResourceUri).did
    if (did && did !== controller) {
      throw new Error('assertionMethod must be controlled by the supplied DID')
    }
    keyUri = key as DidResourceUri
    didUri = controller
  } else {
    if (!did) {
      throw new Error('Credential subject (DID) not supplied and not contained within assertionMethod')
    }
    didUri = did
    keyUri = `${did}${key.startsWith('#') ? '' : '#'}${key}` as DidResourceUri
  }

  await connect(nodeAddress)
  const keypair = new Keyring({ type: keyType }).addFromUri(seed)
  const signCallback: SignCallback = async ({ data }) => ({ signature: keypair.sign(data), keyUri, keyType })
  const credential = await createCredential(signCallback, origin, didUri)
  return credential
}

async function write(toWrite: unknown, outPath?: string) {
  const stringified = JSON.stringify(toWrite, null, 2)
  if (outPath) {
    await writeFile(outPath, stringified)
  } else {
    console.log(stringified)
  }
}

async function run() {
  const args = await yargs(process.argv.slice(2))
    .command(
      'fromCredential <pathToCredential>',
      'create a Did Configuration Resource from an existing Kilt Credential Presentation',
      (ygs) =>
        ygs
          .options({
            outFile: { alias: 'f', type: 'string' },
          })
          .positional('pathToCredential', {
            describe: 'Path to a json file containing the credential presentation',
            type: 'string',
            demandOption: true,
          }),
      async ({ pathToCredential, outFile }) => {
        try {
          let credential: ICredentialPresentation
          try {
            credential = JSON.parse(await readFile(pathToCredential, { encoding: 'utf-8' }))
            if (!Credential.isPresentation(credential)) {
              throw new Error('Malformed Credential Presentation')
            }
          } catch (cause) {
            throw new Error('pathToCredential does not resolve to a valid Kilt Credential Presentation', { cause })
          }
          let didResource: DidConfigResource
          try {
            didResource = await makeDidConfigResourceFromCredential(credential)
          } catch (cause) {
            throw new Error('Credential Presentation is not suitable for use in a Did Configuration Resource', {
              cause,
            })
          }
          await write(didResource, outFile)
        } catch (cause) {
          console.error(cause)
        }
      }
    )
    .command(
      'credentialOnly',
      'issue a new Kilt Credential Presentation for use in a Did Configuration Resource',
      {
        origin: { alias: 'o', type: 'string', demandOption: true },
        did: {
          alias: 'd',
          type: 'string',
          description:
            'DID of the issuer (and subject) of the Domain Linkage Credential. If omitted, this is attempted to be inferred from the assertionMethod.',
        },
        assertionMethod: {
          alias: 'k',
          type: 'string',
          demandOption: true,
          description:
            'URI (or URI fragment, if DID is specified) identifying the assertionMethod key of the issuer (and subject) of the Domain Linkage Credential.',
        },
        seed: {
          type: 'string',
          alias: 's',
          description: 'Mnemonic or seed for the assertionMethod key to be used for issuing a new credential.',
          demandOption: true,
        },
        keyType: { alias: 't', choices: ['sr25519', 'ed25519', 'ecdsa'], default: 'sr25519' },
        outFile: { alias: 'f', type: 'string' },
        wsAddress: { alias: 'w', type: 'string', demandOption: true, default: 'wss://spiritnet.kilt.io' },
      },
      async ({ assertionMethod, origin, seed, keyType, wsAddress, outFile, did }) => {
        try {
          const credential = await issueCredential(
            assertionMethod,
            did as DidUri,
            origin,
            seed,
            keyType as KeyType,
            wsAddress
          )
          await write(credential, outFile)
        } catch (cause) {
          console.error(cause)
        }
      }
    )
    .command(
      '$0',
      'create a Did Configuration Resource from a freshly issued Kilt Credential',
      {
        origin: { alias: 'o', type: 'string', demandOption: true },
        did: {
          alias: 'd',
          type: 'string',
          description:
            'DID of the issuer (and subject) of the Domain Linkage Credential. If omitted, this is attempted to be inferred from the assertionMethod.',
        },
        assertionMethod: {
          alias: 'k',
          type: 'string',
          demandOption: true,
          description:
            'URI (or URI fragment, if DID is specified) identifying the assertionMethod key of the issuer (and subject) of the Domain Linkage Credential.',
        },
        seed: {
          type: 'string',
          alias: 's',
          description: 'Mnemonic or seed for the assertionMethod key to be used for issuing a new credential.',
          demandOption: true,
        },
        keyType: { alias: 't', choices: ['sr25519', 'ed25519', 'ecdsa'], default: 'sr25519' },
        outFile: { alias: 'f', type: 'string' },
        wsAddress: { alias: 'w', type: 'string', demandOption: true, default: 'wss://spiritnet.kilt.io' },
      },
      async ({ assertionMethod, origin, seed, keyType, wsAddress, outFile, did }) => {
        try {
          const credential = await issueCredential(
            assertionMethod,
            did as DidUri,
            origin,
            seed,
            keyType as KeyType,
            wsAddress
          )
          const didResource = await makeDidConfigResourceFromCredential(credential)
          await write(didResource, outFile)
        } catch (cause) {
          console.error(cause)
        }
      }
    )
    .parseAsync()
}

run()
  .catch((e) => console.error(e))
  .finally(disconnect)
