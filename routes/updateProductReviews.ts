/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'

// vuln-code-snippet start noSqlReviewsChallenge forgedReviewChallenge
export function updateProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req) // vuln-code-snippet vuln-line forgedReviewChallenge
    db.reviewsCollection.get(req.body.id).then(async (doc: any) => {
      const originalDoc = { ...doc }
      doc.message = req.body.message
      await db.reviewsCollection.put(doc)

      const result = {
        modified: 1,
        original: [originalDoc],
        updated: [doc]
      }

      challengeUtils.solveIf(challenges.noSqlReviewsChallenge, () => result.modified > 1)
      challengeUtils.solveIf(challenges.forgedReviewChallenge, () => user?.data && originalDoc.author !== user.data.email && result.modified === 1)

      res.json(result)
    }).catch((err) => {
      res.status(500).json(err)
    })
  }
}
// vuln-code-snippet end noSqlReviewsChallenge forgedReviewChallenge
