# -*- coding: utf-8 -*-

def parsePrivileges(privileges):
    """Funkcja parsuje uprawnienia z checkboxów z tabeli do formatu: [index(0/1), kolumna, wiersz]"""
    return [
        [1 if p[0].isChecked() else 0,
        p[1][1],
        p[1][0]]
        for p in privileges
        ]

def findChanges(current_privileges, changed_privileges):
        """Funkcja sprawdza czy uprawnienia zostały zmienione, jeśli tak to zwraca pozycję danego uprawnienia w tabeli i nowe uprawnienie"""
        info = []
        for index, privilege in enumerate(current_privileges):
                if privilege != changed_privileges[index]:
                        info.append(changed_privileges[index])
        return info

def getPrivilegeEditionSql(data, objectDetails):
        """Funkcja zwraca kod sql nadający lub odbierający uprawnienia dla podanych danych"""
        if objectDetails['table']:
                if data['value'] == 1:
                        sql = """GRANT {} ON {}.{} TO {};""".format(
                                data['privilege'],
                                objectDetails['schema'],
                                objectDetails['table'],
                                data['user']
                        )
                else:
                        sql = """REVOKE {} ON {}.{} FROM {};""".format(
                                data['privilege'],
                                objectDetails['schema'],
                                objectDetails['table'],
                                data['user']
                        )
        else:
                if data['value'] == 1:
                        sql = """GRANT {} ON schema {} TO {};""".format(
                                data['privilege'],
                                objectDetails['schema'],
                                data['user']
                        )
                else:
                        sql = """REVOKE {} ON schema {} FROM {};""".format(
                                data['privilege'],
                                objectDetails['schema'],
                                data['user']
                        )
        return sql


def getAllPrivilegesForUser(db, username, schemas_tables):
        """Pobiera uprawnienia użytkownika do wszystkich tabel i schematów z bazy"""
        tables_privileges = {}
        for k, v in schemas_tables.items():
                for table_name in v:
                        if isinstance(table_name, str):
                                cr = db.cursor()
                                cr.execute("""set search_path to '{}';
                                        select a.tablename,HAS_TABLE_PRIVILEGE(usename,tablename, 'select') as select,
                                        HAS_TABLE_PRIVILEGE(usename,tablename, 'insert') as insert,
                                        HAS_TABLE_PRIVILEGE(usename,tablename, 'update') as update,
                                        HAS_TABLE_PRIVILEGE(usename,tablename, 'delete') as delete
                                        from pg_tables a , pg_user b 
                                        where a.tablename='{}' and b.usename='{}';""".format(
                                                k, table_name, username
                                        )
                                )
                                try:
                                        prv_data = cr.fetchall()[0]
                                        if k not in tables_privileges.keys():
                                                tables_privileges.update({k: {prv_data[0]: list(prv_data[1:])}})
                                        else:
                                                tables_privileges[k].update({prv_data[0]: list(prv_data[1:])})
                                except:
                                        pass
                                db.rollback()
                                del cr
        schemas_privileges = []
        for k in schemas_tables.keys():
                cr = db.cursor()
                cr.execute(
                        """
                        SELECT n.nspname AS schema_name,
                         p.perm AS privilege
                        FROM pg_catalog.pg_namespace AS n
                         CROSS JOIN pg_catalog.pg_roles AS r
                         CROSS JOIN (VALUES ('USAGE'), ('CREATE')) AS p(perm)
                        WHERE has_schema_privilege(r.oid, n.oid, p.perm)
                         AND n.nspname like '{}'
	                 AND r.rolname like '{}'
                         """.format(
                                 k, username
                         )
                )
                sch_data = cr.fetchall()
                for privilege in sch_data:
                        schemas_privileges.append({
                                privilege[0]: privilege[1]
                        })
                db.rollback()
                del cr
        return schemas_privileges, tables_privileges

def updateAllUserPrivileges(db, user, schemas_privileges, tables_privileges):
        """Aktualizuje uprawnienia do schematów i tabel dla wskazango usera"""
        sql = ''
        privileges_keys = ['SELECT', 'INSERT', 'UPDATE', 'DELETE']
        for k, v in tables_privileges.items():
                for table_name, table_privileges in v.items():
                        for index, privilege in enumerate(table_privileges):
                                if privilege:
                                        sql += """GRANT {} ON {}.{} TO {};""".format(
                                                privileges_keys[index], k, table_name, user
                                )
        for privilege in schemas_privileges:
                for k, v in privilege.items():
                        sql += """GRANT {} ON SCHEMA {} TO {};""".format(
                                v, k, user
                        )
        cr = db.cursor()
        cr.execute(sql)
        db.rollback()
        del cr

def revokeAllUserPrivileges(db, user, schemas_tables):
        cr = db.cursor()
        sql = ''
        for k in schemas_tables.keys():
                sql += """
                REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA {} FROM {};
                REVOKE USAGE ON SCHEMA {} FROM {};
                REVOKE CREATE ON SCHEMA {} FROM {};
                """.format(
                        k, user, k, user, k, user
                )
        cr.execute(sql)
        db.rollback()
        del cr

def checkSuperUser(db, username):
        cr = db.cursor()
        cr.execute('select usesuper from pg_user where usename = {};'.format(username))
        result = cr.fetchall()[0][0]
        db.rollback()
        del cr
        return result

