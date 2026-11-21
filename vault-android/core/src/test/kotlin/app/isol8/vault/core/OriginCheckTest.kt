package app.isol8.vault.core

import kotlin.test.Test
import kotlin.test.assertEquals

class OriginCheckTest {
    @Test
    fun officialOriginPassesInEveryBuild() {
        assertEquals(Pairing.OriginCheck.OFFICIAL, Pairing.checkOrigin("isol8.app", developmentBuild = false))
        assertEquals(Pairing.OriginCheck.OFFICIAL, Pairing.checkOrigin("isol8.app", developmentBuild = true))
    }

    @Test
    fun releaseBuildsBlockEverythingElse() {
        // Lookalikes, subdomains, the redirect-only domains and near misses are all blocked.
        for (o in listOf("isol8-app.example", "isol8.app.example", "www.isol8.app", "staging.isol8.app", "isol8app.com", "isol8.xyz", "is0l8.app", "isol8.ap")) {
            assertEquals(Pairing.OriginCheck.BLOCK, Pairing.checkOrigin(o, developmentBuild = false), o)
            assertEquals(Pairing.OriginCheck.WARN, Pairing.checkOrigin(o, developmentBuild = true), o)
        }
    }
}
