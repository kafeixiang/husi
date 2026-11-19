@file:Suppress("ClassName")

package fr.husi.database

import androidx.room3.DeleteColumn
import androidx.room3.migration.AutoMigrationSpec
import androidx.room3.migration.Migration
import androidx.sqlite.SQLiteConnection
import androidx.sqlite.execSQL

@DeleteColumn.Entries(
    DeleteColumn(
        tableName = "proxy_entities",
        columnName = "nekoBean",
    ),
)
class SagerDatabase_Migration_2_3 : AutoMigrationSpec

object SagerDatabase_Migration_3_4 : Migration(3, 4) {
    override suspend fun migrate(connection: SQLiteConnection) {
        connection.execSQL("""ALTER TABLE `rules` ADD `clientType` TEXT NOT NULL DEFAULT ''""")
    }
}

object SagerDatabase_Migration_4_5 : Migration(4, 5) {
    override suspend fun migrate(connection: SQLiteConnection) {
        connection.execSQL("""ALTER TABLE `rules` ADD `clashMode` TEXT NOT NULL DEFAULT ''""")
    }
}

@DeleteColumn.Entries(
    DeleteColumn(
        tableName = "proxy_entities",
        columnName = "trojanGoBean",
    ),
    DeleteColumn(
        tableName = "rules",
        columnName = "ruleSet",
    ),
)
class SagerDatabase_Migration_5_6 : AutoMigrationSpec

object SagerDatabase_Migration_6_7 : Migration(6, 7) {
    override suspend fun migrate(connection: SQLiteConnection) {
        connection.execSQL("DELETE FROM proxy_entities WHERE type = " + ProxyEntity.TYPE_TROJAN_GO.toString())
        connection.execSQL("DELETE FROM proxy_entities WHERE type = " + ProxyEntity.TYPE_NEKO.toString())
    }
}

@DeleteColumn.Entries(
    DeleteColumn(
        tableName = "proxy_groups",
        columnName = "isSelector",
    ),
)
class SagerDatabase_Migration_12_13 : AutoMigrationSpec

@DeleteColumn.Entries(
    DeleteColumn(
        tableName = "proxy_entities",
        columnName = "uuid",
    ),
)
class SagerDatabase_Migration_14_15 : AutoMigrationSpec

@DeleteColumn.Entries(
    DeleteColumn(
        tableName = "proxy_groups",
        columnName = "frontProxy",
    ),
    DeleteColumn(
        tableName = "proxy_groups",
        columnName = "landingProxy",
    ),
)
class SagerDatabase_Migration_22_23 : AutoMigrationSpec

object SagerDatabase_Migration_25_26 : Migration(25, 26) {
    override suspend fun migrate(connection: SQLiteConnection) {
        val columns = mutableSetOf<String>()
        connection.prepare("PRAGMA table_info(`proxy_entities`)").use { statement ->
            while (statement.step()) {
                columns.add(statement.getText(1))
            }
        }
        if (!columns.contains("ssrBean")) {
            connection.execSQL("ALTER TABLE `proxy_entities` ADD COLUMN `ssrBean` BLOB DEFAULT NULL")
        }
        if (!columns.contains("trojanGoBean")) {
            connection.execSQL("ALTER TABLE `proxy_entities` ADD COLUMN `trojanGoBean` BLOB DEFAULT NULL")
        }
    }
}

