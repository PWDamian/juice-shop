/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { type Review } from '../data/types'
import * as db from '../data/mongodb'

const sleep = async (ms: number) => await new Promise(resolve => setTimeout(resolve, ms))

export function likeProductReviews () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const id = req.body.id
    const user = security.authenticatedUsers.from(req)
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' })
    }

    try {
      const review: any = await db.reviewsCollection.get(id)
      if (!review) {
        return res.status(404).json({ error: 'Not found' })
      }

      const likedBy = review.likedBy
      if (likedBy.includes(user.data.email)) {
        return res.status(403).json({ error: 'Not allowed' })
      }

      try {
        const doc: any = await db.reviewsCollection.get(id)
        doc.likesCount = doc.likesCount + 1
        await db.reviewsCollection.put(doc)
      } catch (err) {
        console.error('Error updating like count:', err)
      }

      // Artificial wait for timing attack challenge
      await sleep(150)
      try {
        const updatedReview: Review = await db.reviewsCollection.get(id)
        const updatedLikedBy = updatedReview.likedBy
        updatedLikedBy.push(user.data.email)

        const count = updatedLikedBy.filter(email => email === user.data.email).length
        challengeUtils.solveIf(challenges.timingAttackChallenge, () => count > 2)

        const doc: any = await db.reviewsCollection.get(id)
        doc.likedBy = updatedLikedBy
        await db.reviewsCollection.put(doc)
        res.json(doc)
      } catch (err) {
        res.status(500).json(err)
      }
    } catch (err) {
      res.status(400).json({ error: 'Wrong Params' })
    }
  }
}
