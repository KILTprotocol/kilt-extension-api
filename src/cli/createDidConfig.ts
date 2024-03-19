#!/usr/bin/env node

/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { createSigner as eddsaSigner } from '@kiltprotocol/eddsa-jcs-2022'
import { createSigner as es256kSigner } from '@kiltprotocol/es256k-jcs-2023'
import { ConformingDidDocument, Did, DidResourceUri, DidUri, connect, disconnect } from '@kiltprotocol/sdk-js'
import { createSigner as sr25519Signer } from '@kiltprotocol/sr25519-jcs-2023'

import Keyring from '@polkadot/keyring'
import { decodePair } from '@polkadot/keyring/pair/decode'
import { u8aEq } from '@polkadot/util'
import { base58Decode } from '@polkadot/util-crypto'

import { readFile, writeFile } from 'fs/promises'
import yargs from 'yargs/yargs'

import { DidConfigResource, DomainLinkageCredential } from '../types/Credential.js'
import {
  DATA_INTEGRITY_PROOF_TYPE,
  KILT_SELF_SIGNED_PROOF_TYPE,
  createCredential,
  didConfigResourceFromCredentials,
  verifyDomainLinkageCredential,
} from '../wellKnownDidConfiguration/index.js'

type KeyType = 'sr25519' | 'ed25519' | 'ecdsa'

const commonOpts = { outFile: { alias: 'f', type: 'string' } } as const
const createCredentialOpts = {
  origin: { alias: 'o', type: 'string', demandOption: true },
  did: {
    alias: 'd',
    type: 'string',
    demandOption: true,
    description:
      'DID of the issuer (and subject) of the Domain Linkage Credential. If omitted, attempts to infer from the assertionMethod.',
  },
  seed: {
    type: 'string',
    alias: 's',
    description: 'Mnemonic or seed for the assertionMethod key to be used for issuing a new credential.',
    demandOption: true,
  },
  keyType: { alias: 't', choices: ['sr25519', 'ed25519', 'ecdsa'] as const, default: 'ed25519' },
  wsAddress: { alias: 'w', type: 'string', demandOption: true, default: 'wss://spiritnet.kilt.io' },
} as const

async function issueCredential(did: string, origin: string, seed: string, keyType: KeyType, proofType?: string) {
  const { didDocument } = await Did.resolveCompliant(did as DidUri)
  const assertionMethodId = didDocument?.assertionMethod?.[0]
  const assertionMethod = didDocument?.verificationMethod?.find(({ id }) => id.endsWith(assertionMethodId ?? '<none>'))
  if (!assertionMethod) {
    throw new Error(
      `Could not resolve assertionMethod of ${did}. Make sure the DID is registered to this chain and has an assertionMethod key.`
    )
  }
  // generate keypair and extract private key
  const keypair = new Keyring().addFromUri(seed, undefined, keyType)
  const { secretKey } = decodePair(undefined, keypair.encodePkcs8(), 'none')
  if (!u8aEq(keypair.publicKey, base58Decode(assertionMethod.publicKeyBase58))) {
    throw new Error('seed does not match DID assertion method')
  }
  // create signer
  const keyUri: DidResourceUri = assertionMethod.id
  const createSigner = {
    sr25519: sr25519Signer,
    ed25519: eddsaSigner,
    ecdsa: es256kSigner,
  }
  const signer = await createSigner[keyType]({ id: keyUri, secretKey, publicKey: keypair.publicKey })

  const credential = await createCredential(
    signer,
    origin,
    didDocument as ConformingDidDocument,
    { proofType } as { proofType: typeof DATA_INTEGRITY_PROOF_TYPE | typeof KILT_SELF_SIGNED_PROOF_TYPE }
  )

  await verifyDomainLinkageCredential(credential, origin, { expectedDid: did as DidUri })

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
  await yargs(process.argv.slice(2))
    .command(
      'fromCredential [pathToCredential..]',
      'create a Did Configuration Resource from one or more existing Domain Linkage Credentials',
      (ygs) =>
        ygs.options(commonOpts).positional('pathToCredential', {
          describe: 'Path to a json file containing a Domain Linkage Credential',
          type: 'string',
          demandOption: true,
          array: true,
        }),
      async ({ pathToCredential, outFile }) => {
        const credentials: DomainLinkageCredential[] = await Promise.all(
          pathToCredential.map(async (path) => {
            try {
              return JSON.parse(await readFile(path, { encoding: 'utf-8' }))
            } catch (cause) {
              throw new Error(`Cannot parse file ${pathToCredential}`, { cause })
            }
          })
        )
        let didResource: DidConfigResource
        try {
          didResource = didConfigResourceFromCredentials(credentials)
        } catch (cause) {
          throw new Error('Credential is not suitable for use in a Did Configuration Resource', {
            cause,
          })
        }
        await write(didResource, outFile)
      }
    )
    .command(
      'credentialOnly',
      'issue a new Domain Linkage Credential for use in a Did Configuration Resource',
      {
        ...createCredentialOpts,
        ...commonOpts,
        proofType: {
          alias: 'p',
          choices: [DATA_INTEGRITY_PROOF_TYPE, KILT_SELF_SIGNED_PROOF_TYPE] as const,
          default: KILT_SELF_SIGNED_PROOF_TYPE,
          describe:
            'Which proof type to use in the credential. DataIntegrity is the more modern proof type, but might not be accepted by all extensions yet. Did Configuration Resources can contain multiple credentials, though.',
        },
      },
      async ({ origin, seed, keyType, wsAddress, outFile, did, proofType }) => {
        await connect(wsAddress)
        const credential = await issueCredential(did, origin, seed, keyType, proofType)
        await write(credential, outFile)
      }
    )
    .command(
      '$0',
      'create a Did Configuration Resource containing newly issued Domain Linkage Credentials',
      { ...createCredentialOpts, ...commonOpts },
      async ({ origin, seed, keyType, wsAddress, outFile, did }) => {
        await connect(wsAddress)
        const credentials = await Promise.all(
          [DATA_INTEGRITY_PROOF_TYPE, KILT_SELF_SIGNED_PROOF_TYPE].map((proofType) =>
            issueCredential(did, origin, seed, keyType, proofType)
          )
        )
        const didResource = didConfigResourceFromCredentials(credentials)
        await write(didResource, outFile)
      }
    )
    .parseAsync()
}

run()
  .catch(async (e) => {
    process.exitCode = 1
    console.error(e)
  })
  .finally(disconnect)
