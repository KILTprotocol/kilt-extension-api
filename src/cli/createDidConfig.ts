#!/usr/bin/env node

/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { DataIntegrity } from '@kiltprotocol/credentials'
import { multibaseKeyToDidKey } from '@kiltprotocol/did'
import { DidResolver, connect, disconnect } from '@kiltprotocol/sdk-js'
import { Did, DidUrl } from '@kiltprotocol/types'
import { Signers } from '@kiltprotocol/utils'

import { Keyring } from '@polkadot/keyring'
import { u8aEq } from '@polkadot/util'

import { readFile, writeFile } from 'fs/promises'
import yargs from 'yargs/yargs'

import { DidConfigResource, DomainLinkageCredential } from '../types/Credential.js'
import {
  KILT_SELF_SIGNED_PROOF_TYPE,
  createCredential,
  didConfigResourceFromCredentials,
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

async function issueCredential(did: string, origin: string, seed: string, keyType: KeyType, proofType: string) {
  const { didDocument } = await DidResolver.resolve(did as Did, {})
  const assertionMethodId = didDocument?.assertionMethod?.[0]
  const assertionMethod = didDocument?.verificationMethod?.find(({ id }) => id === assertionMethodId)
  if (!assertionMethod) {
    throw new Error(
      `Could not resolve assertionMethod of ${did}. Make sure the DID is registered to this chain and has an assertionMethod key.`
    )
  }
  const keyUri: DidUrl = `${didDocument!.id}${assertionMethod.id}`

  const keypair = new Keyring({ type: keyType }).addFromUri(seed)
  const signers = await Signers.getSignersForKeypair({ keypair, id: keyUri })

  const { keyType: vmType, publicKey } = multibaseKeyToDidKey(assertionMethod.publicKeyMultibase)
  if (vmType !== keypair.type || !u8aEq(publicKey, keypair.publicKey)) {
    throw new Error('public key and/or key type of the DIDs assertionMethod does not match the supplied signing key')
  }

  const credential = await createCredential(signers, origin, didDocument!, { proofType } as any)

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
          choices: [DataIntegrity.PROOF_TYPE, KILT_SELF_SIGNED_PROOF_TYPE] as const,
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
          [DataIntegrity.PROOF_TYPE, KILT_SELF_SIGNED_PROOF_TYPE].map((proofType) =>
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
