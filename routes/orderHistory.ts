/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import { ordersCollection } from '../data/mongodb'
import * as security from '../lib/insecurity'

export function orderHistory () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.headers?.authorization?.replace('Bearer ', ''))
    if (loggedInUser?.data?.email && loggedInUser.data.id) {
      const email = loggedInUser.data.email
      const updatedEmail = email.replace(/[aeiou]/gi, '*')
      const result = await ordersCollection.find({
        selector: { email: updatedEmail }
      })
      const order = result.docs

      res.status(200).json({ status: 'success', data: order })
    } else {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}

export function allOrders () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const result = await ordersCollection.allDocs({ include_docs: true })
    const orders = result.rows.map(row => row.doc)
    res.status(200).json({ status: 'success', data: orders.reverse() })
  }
}

export function toggleDeliveryStatus () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const deliveryStatus = !req.body.deliveryStatus
    const eta = deliveryStatus ? '0' : '1'
    const doc: any = await ordersCollection.get(req.params.id)
    doc.delivered = deliveryStatus
    doc.eta = eta
    await ordersCollection.put(doc)
    res.status(200).json({ status: 'success' })
  }
}
