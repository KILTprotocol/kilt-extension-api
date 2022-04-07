// @ts-ignore
import { useState, useEffect } from 'react'
import { getExtensions } from './getExtension'
import { InjectedWindowProvider } from '../types/types'

export default function reactExample() {
  const [extensionEnabled, setExtensionEnabled] = useState(false)
  const [extensions, setExtensions] = useState<InjectedWindowProvider[]>()
  useEffect(() => {
    async function doEffect() {
      const allInjected = await getExtensions()
      if (allInjected) {
        setExtensions(allInjected)
      }
      setExtensionEnabled(true)
    }
    doEffect()
  }, [])
  useEffect(() => {
    async function doEffect() {
      if (extensionEnabled) {
        console.log(extensions)
      }
    }
    doEffect()
  }, [extensionEnabled, extensions])
  return `<div>Add your logic app here</div>`
}
