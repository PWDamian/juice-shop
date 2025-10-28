/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import PouchDB from 'pouchdb'
import PouchFind from 'pouchdb-find'
import fs from 'node:fs'
import path from 'node:path'

PouchDB.plugin(PouchFind)

const storageDir = path.join(__dirname, 'nosql') + path.sep

fs.mkdirSync(storageDir, { recursive: true })

const Pouch = PouchDB.defaults({ prefix: storageDir })

export const reviewsCollection = new Pouch('posts')
export const ordersCollection = new Pouch('orders')
