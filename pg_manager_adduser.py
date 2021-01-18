from PyQt5 import uic
from PyQt5 import QtWidgets
from qgis.core import Qgis
from copy import deepcopy

import os
import psycopg2

from .pg_manager_utils import parsePrivileges, getAllPrivilegesForUser, updateAllUserPrivileges

# This loads your .ui file so that PyQt can populate your plugin with the elements from Qt Designer
FORM_CLASS, _ = uic.loadUiType(os.path.join(
    os.path.dirname(__file__), 'Ui_pg_manager_adduser.ui'))

class pgmanagerAddUser(QtWidgets.QDialog, FORM_CLASS):

    username = None
    password = None

    def __init__(self, parent, parents=None):
        super(pgmanagerAddUser, self).__init__(parents)

        self.setupUi(self)

        self.parent = parent
        self.btnApply.clicked.connect(self.createUser)
        self.btnCancel.clicked.connect(self.close)
        self.chCopyPrivileges.stateChanged.connect(self.copyPrivileges)
        self.copy_privileges = False

    def close(self):
        self.reject()

    def createUser(self):
        username = self.lnUsername.text()
        password = self.lnPassword.text()
        user_to_copy = self.lnExistingUsername.text()
        if len(password) < 6:
            self.parent.showMessage(
                'Podane hasło jest za krótkie. Hasło musi zawierać co najmniej 5 znaków',
                Qgis.Critical,
                3,
                'Bład'
            )
            return
        try:
            cur = self.parent.database.cursor()
            cur.execute(
                """create role {} with LOGIN PASSWORD '{}';"""
                .format(username, password)
            )
            self.parent.database.rollback()
            del cur
        except psycopg2.ProgrammingError:
            self.parent.showMessage(
                'Użytkownik o podanej nazwie już istnieje lub nazwa użytkownika zawiera niedozwolone znaki',
                Qgis.Critical,
                2,
                'Błąd'
            )
            return
        if self.copy_privileges:
            if not self.lnExistingUsername.text():
                self.parent.showMessage(
                    'Nie podano nazwy użytkownika, z której skopiowane mają zostać uprawnienia',
                    Qgis.Critical,
                    3,
                    'Błąd'
                )
                return
            else:
                schemas_tables = self.parent.getSchemasAndTables(self.parent.database)
                privileges_user_to_copy = getAllPrivilegesForUser(
                    self.parent.database, user_to_copy, schemas_tables
                )
                updateAllUserPrivileges(
                    self.parent.database, username, privileges_user_to_copy[0], privileges_user_to_copy[1]
                )
        self.accept()
        self.reloadParentPrivilegesTable(self.parent.currentObjectType)
        self.parent.showMessage(
            'Pomyślnie stworzono nowego użytkownika',
            Qgis.Info,
            2,
            'Sukces'
        )

    def reloadParentPrivilegesTable(self, objectType):
        if objectType == 'table':
            privileges = self.parent.getPrivileges(
                self.parent.database,
                objectType,
                [self.parent.currentSchemaName, self.parent.currentTableName]
            )
            self.parent.populateTable(self.parent.database, privileges, objectType)
            lp = parsePrivileges(self.parent.getLoadedPrivileges(self.parent.tableWidget))
            self.parent.loadedPrivileges = deepcopy(lp)
        elif objectType == 'schema':
            privileges = self.parent.getPrivileges(
                self.parent.database,
                objectType,
                [self.parent.currentSchemaName]
            )
            self.parent.populateTable(self.parent.database, privileges, objectType)
            lp = parsePrivileges(self.parent.getLoadedPrivileges(self.parent.tableWidget))
            self.parent.loadedPrivileges = deepcopy(lp)
        else:
            pass

    def copyPrivileges(self):
        if self.chCopyPrivileges.isChecked():
            self.lbExistingUsername.setEnabled(True)
            self.lnExistingUsername.setEnabled(True)
            self.copy_privileges = True
        else:
            self.lbExistingUsername.setEnabled(False)
            self.lnExistingUsername.setEnabled(False)
            self.copy_privileges = False
