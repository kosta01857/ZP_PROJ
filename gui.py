import sys
from datetime import datetime
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem,
    QFileDialog, QDialog, QDialogButtonBox, QComboBox, QFormLayout, QMessageBox,
    QGroupBox, QSplitter, QHeaderView,
)
from PyQt6.QtCore import Qt

from user_service import UserService
from main_service import MainService
from exception import SignatureVerificationError


def ask_password(parent, title="Enter Password"):
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    layout = QFormLayout(dlg)
    pwd = QLineEdit()
    pwd.setEchoMode(QLineEdit.EchoMode.Password)
    layout.addRow("Password:", pwd)
    buttons = QDialogButtonBox(
        QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
    )
    buttons.accepted.connect(dlg.accept)
    buttons.rejected.connect(dlg.reject)
    layout.addWidget(buttons)
    if dlg.exec() == QDialog.DialogCode.Accepted:
        return pwd.text()
    return None


class NewUserDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("New User")
        layout = QFormLayout(self)
        self.name_edit = QLineEdit()
        self.email_edit = QLineEdit()
        layout.addRow("Name:", self.name_edit)
        layout.addRow("Email:", self.email_edit)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _accept(self):
        if not self.name_edit.text().strip() or not self.email_edit.text().strip():
            QMessageBox.warning(self, "Error", "Name and email are required.")
            return
        self.accept()

    def get_data(self):
        return self.name_edit.text().strip(), self.email_edit.text().strip()


class GenerateKeyDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Generate Key Pair")
        layout = QFormLayout(self)
        self.size_combo = QComboBox()
        self.size_combo.addItems(["1024", "2048"])
        self.size_combo.setCurrentText("2048")
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_edit = QLineEdit()
        self.confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addRow("Key size (bits):", self.size_combo)
        layout.addRow("Password:", self.password_edit)
        layout.addRow("Confirm password:", self.confirm_edit)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _accept(self):
        if not self.password_edit.text():
            QMessageBox.warning(self, "Error", "Password cannot be empty.")
            return
        if self.password_edit.text() != self.confirm_edit.text():
            QMessageBox.warning(self, "Error", "Passwords do not match.")
            return
        self.accept()

    def get_data(self):
        return int(self.size_combo.currentText()), self.password_edit.text()


class ImportPublicKeyDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Import Public Key")
        layout = QFormLayout(self)
        self.name_edit = QLineEdit()
        self.email_edit = QLineEdit()
        file_row = QHBoxLayout()
        self.file_edit = QLineEdit()
        self.file_edit.setReadOnly(True)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse)
        file_row.addWidget(self.file_edit)
        file_row.addWidget(browse_btn)
        layout.addRow("Name:", self.name_edit)
        layout.addRow("Email:", self.email_edit)
        layout.addRow("PEM file:", file_row)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open PEM file", "", "PEM files (*.pem);;All files (*)"
        )
        if path:
            self.file_edit.setText(path)

    def _accept(self):
        if not self.name_edit.text().strip():
            QMessageBox.warning(self, "Error", "Name is required.")
            return
        if not self.email_edit.text().strip():
            QMessageBox.warning(self, "Error", "Email is required.")
            return
        if not self.file_edit.text():
            QMessageBox.warning(self, "Error", "Please select a PEM file.")
            return
        self.accept()

    def get_data(self):
        return (
            self.name_edit.text().strip(),
            self.email_edit.text().strip(),
            self.file_edit.text(),
        )


class KeyRingTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.mw = main_window
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Private key ring
        priv_group = QGroupBox("Private Key Ring")
        priv_layout = QVBoxLayout(priv_group)
        self.priv_table = QTableWidget(0, 3)
        self.priv_table.setHorizontalHeaderLabels(["Key ID", "Size (bits)", "Created"])
        self.priv_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.priv_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.priv_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        priv_layout.addWidget(self.priv_table)
        priv_btns = QHBoxLayout()
        for label, slot in [
            ("Generate Key Pair", self._generate_key),
            ("Delete Key Pair", self._delete_pair),
            ("Export Private Key", self._export_private),
            ("Export Public Key", self._export_public_from_priv),
        ]:
            btn = QPushButton(label)
            btn.clicked.connect(slot)
            priv_btns.addWidget(btn)
        priv_layout.addLayout(priv_btns)
        splitter.addWidget(priv_group)

        # Public key ring
        pub_group = QGroupBox("Public Key Ring")
        pub_layout = QVBoxLayout(pub_group)
        self.pub_table = QTableWidget(0, 5)
        self.pub_table.setHorizontalHeaderLabels(
            ["Key ID", "Name", "Email", "Size (bits)", "Created"]
        )
        self.pub_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.pub_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.pub_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        pub_layout.addWidget(self.pub_table)
        pub_btns = QHBoxLayout()
        for label, slot in [
            ("Import Public Key", self._import_public),
            ("Export Public Key", self._export_public_from_pub),
        ]:
            btn = QPushButton(label)
            btn.clicked.connect(slot)
            pub_btns.addWidget(btn)
        pub_layout.addLayout(pub_btns)
        splitter.addWidget(pub_group)

        layout.addWidget(splitter)

    def refresh(self):
        user = self.mw.current_user()
        if user is None:
            self.priv_table.setRowCount(0)
            self.pub_table.setRowCount(0)
            return

        priv_keys = user.loadPrivateKeyRing()
        self.priv_table.setRowCount(len(priv_keys))
        for i, k in enumerate(priv_keys):
            self.priv_table.setItem(i, 0, QTableWidgetItem(k["keyId"]))
            self.priv_table.setItem(i, 1, QTableWidgetItem(str(k["keySize"])))
            self.priv_table.setItem(i, 2, QTableWidgetItem(k.get("timestamp", "")))

        pub_keys = user.loadPublicKeyRing()
        self.pub_table.setRowCount(len(pub_keys))
        for i, k in enumerate(pub_keys):
            self.pub_table.setItem(i, 0, QTableWidgetItem(k["keyId"]))
            self.pub_table.setItem(i, 1, QTableWidgetItem(k.get("name", "")))
            self.pub_table.setItem(i, 2, QTableWidgetItem(k.get("email", "")))
            self.pub_table.setItem(i, 3, QTableWidgetItem(str(k["keySize"])))
            self.pub_table.setItem(i, 4, QTableWidgetItem(k.get("timestamp", "")))

    def _generate_key(self):
        user = self.mw.current_user()
        if user is None:
            QMessageBox.warning(self, "No User", "Select or create a user first.")
            return
        dlg = GenerateKeyDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        size, password = dlg.get_data()
        try:
            user.newKeyPair(size, password)
            self.refresh()
            self.mw.refresh_key_selectors()
            priv_keys = user.loadPrivateKeyRing()
            new_key = priv_keys[-1]
            self.mw.log(f"Generated {size}-bit key pair  key_id={new_key['keyId']}  user={user.name}")
        except Exception as e:
            self.mw.log(f"ERROR generating key pair: {e}")
            QMessageBox.critical(self, "Error", str(e))

    def _delete_pair(self):
        user = self.mw.current_user()
        if user is None:
            return
        row = self.priv_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "No Selection", "Select a key pair to delete.")
            return
        key_id = self.priv_table.item(row, 0).text()
        if QMessageBox.question(self, "Confirm", f"Delete key pair {key_id}?") != QMessageBox.StandardButton.Yes:
            return
        priv_keys = user.loadPrivateKeyRing()
        entry = next((k for k in priv_keys if k["keyId"] == key_id), None)
        if entry:
            user.deleteKeyPair(entry)
            self.refresh()
            self.mw.refresh_key_selectors()
            self.mw.log(f"Deleted key pair  key_id={key_id}  user={user.name}")

    def _export_private(self):
        user = self.mw.current_user()
        if user is None:
            return
        row = self.priv_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "No Selection", "Select a key to export.")
            return
        key_id = self.priv_table.item(row, 0).text()
        password = ask_password(self, "Enter Key Password")
        if password is None:
            return
        dest, _ = QFileDialog.getSaveFileName(self, "Save Private Key", "", "PEM files (*.pem)")
        if not dest:
            return
        if user.exportPrivateKey(key_id, password.encode(), dest):
            self.mw.log(f"Exported private key  key_id={key_id}  -> {dest}")
            QMessageBox.information(self, "Success", "Private key exported.")
        else:
            self.mw.log(f"ERROR exporting private key  key_id={key_id}  (wrong password?)")
            QMessageBox.critical(self, "Error", "Export failed. Wrong password?")

    def _export_public_from_priv(self):
        user = self.mw.current_user()
        if user is None:
            return
        row = self.priv_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "No Selection", "Select a key to export.")
            return
        key_id = self.priv_table.item(row, 0).text()
        dest, _ = QFileDialog.getSaveFileName(self, "Save Public Key", "", "PEM files (*.pem)")
        if not dest:
            return
        if user.exportPublicKey(key_id, dest):
            self.mw.log(f"Exported public key  key_id={key_id}  -> {dest}")
            QMessageBox.information(self, "Success", "Public key exported.")
        else:
            self.mw.log(f"ERROR exporting public key  key_id={key_id}")
            QMessageBox.critical(self, "Error", "Export failed.")

    def _import_public(self):
        user = self.mw.current_user()
        if user is None:
            QMessageBox.warning(self, "No User", "Select or create a user first.")
            return
        dlg = ImportPublicKeyDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        name, email, filepath = dlg.get_data()
        try:
            pub = user.importPublicKey(name, email, filepath)
            self.refresh()
            self.mw.refresh_key_selectors()
            pub_keys = user.loadPublicKeyRing()
            imported = next((k for k in pub_keys if k["email"] == email), None)
            key_id = imported["keyId"] if imported else "?"
            self.mw.log(f"Imported public key  key_id={key_id}  name={name} <{email}>  into user={user.name}")
        except Exception as e:
            self.mw.log(f"ERROR importing public key from {filepath}: {e}")
            QMessageBox.critical(self, "Error", str(e))

    def _export_public_from_pub(self):
        user = self.mw.current_user()
        if user is None:
            return
        row = self.pub_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "No Selection", "Select a key to export.")
            return
        key_id = self.pub_table.item(row, 0).text()
        dest, _ = QFileDialog.getSaveFileName(self, "Save Public Key", "", "PEM files (*.pem)")
        if not dest:
            return
        if user.exportPublicKey(key_id, dest):
            self.mw.log(f"Exported public key  key_id={key_id}  -> {dest}")
            QMessageBox.information(self, "Success", "Public key exported.")
        else:
            self.mw.log(f"ERROR exporting public key  key_id={key_id}")
            QMessageBox.critical(self, "Error", "Export failed.")


class SendTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.mw = main_window
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        msg_group = QGroupBox("Message")
        msg_layout = QVBoxLayout(msg_group)
        self.message_edit = QTextEdit()
        self.message_edit.setPlaceholderText("Enter your message here...")
        msg_layout.addWidget(self.message_edit)
        layout.addWidget(msg_group)

        keys_row = QHBoxLayout()

        sign_group = QGroupBox("Sign with (Private Key)")
        sign_layout = QFormLayout(sign_group)
        self.sign_key_combo = QComboBox()
        self.sign_password_edit = QLineEdit()
        self.sign_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.sign_password_edit.setPlaceholderText("Password for private key")
        sign_layout.addRow("Key:", self.sign_key_combo)
        sign_layout.addRow("Password:", self.sign_password_edit)
        keys_row.addWidget(sign_group)

        enc_group = QGroupBox("Encrypt for (Public Key)")
        enc_layout = QFormLayout(enc_group)
        self.enc_key_combo = QComboBox()
        self.algo_combo = QComboBox()
        self.algo_combo.addItems(["AES", "3DES"])
        enc_layout.addRow("Recipient key:", self.enc_key_combo)
        enc_layout.addRow("Algorithm:", self.algo_combo)
        keys_row.addWidget(enc_group)

        layout.addLayout(keys_row)

        dest_group = QGroupBox("Output File")
        dest_layout = QHBoxLayout(dest_group)
        self.dest_edit = QLineEdit()
        self.dest_edit.setReadOnly(True)
        self.dest_edit.setPlaceholderText("Choose destination file...")
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_dest)
        dest_layout.addWidget(self.dest_edit)
        dest_layout.addWidget(browse_btn)
        layout.addWidget(dest_group)

        send_btn = QPushButton("Send")
        send_btn.setFixedHeight(40)
        send_btn.clicked.connect(self._send)
        layout.addWidget(send_btn)

    def refresh_keys(self, priv_keys, pub_keys):
        self.sign_key_combo.clear()
        for k in priv_keys:
            self.sign_key_combo.addItem(f"{k['keyId']}  ({k['keySize']} bit)", k["keyId"])

        self.enc_key_combo.clear()
        for k in pub_keys:
            label = f"{k['keyId']}  {k.get('name', '')} <{k.get('email', '')}>"
            self.enc_key_combo.addItem(label, k["keyId"])

    def _browse_dest(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Message", "", "PGP files (*.pgp);;All files (*)"
        )
        if path:
            self.dest_edit.setText(path)

    def _send(self):
        user = self.mw.current_user()
        if user is None:
            QMessageBox.warning(self, "No User", "Select or create a user first.")
            return
        if not self.message_edit.toPlainText():
            QMessageBox.warning(self, "Error", "Message cannot be empty.")
            return
        if self.sign_key_combo.count() == 0:
            QMessageBox.warning(self, "Error", "No private keys available for signing.")
            return
        if self.enc_key_combo.count() == 0:
            QMessageBox.warning(self, "Error", "No public keys available for encryption.")
            return
        dest = self.dest_edit.text()
        if not dest:
            QMessageBox.warning(self, "Error", "Choose a destination file.")
            return

        sign_key_id = self.sign_key_combo.currentData()
        enc_key_id = self.enc_key_combo.currentData()
        algorithm = self.algo_combo.currentText()

        self.mw.log(f"SEND  user={user.name}  sign_key={sign_key_id}  enc_key={enc_key_id}  algo={algorithm}  dest={dest}")

        password = self.sign_password_edit.text()
        priv_key = user.getPrivateKey(sign_key_id, password.encode())
        if priv_key is None:
            self.mw.log(f"ERROR: failed to load private key {sign_key_id} (wrong password?)")
            QMessageBox.critical(self, "Error", "Failed to load private key. Wrong password?")
            return
        self.mw.log(f"  signing key loaded  key_size={priv_key.key_size}")

        pub_key = user.getPublicKey(enc_key_id)
        if pub_key is None:
            self.mw.log(f"ERROR: failed to load public key {enc_key_id}")
            QMessageBox.critical(self, "Error", "Failed to load recipient's public key.")
            return
        self.mw.log(f"  encryption key loaded  key_size={pub_key.key_size}")

        try:
            self.mw.main_svc.send(
                self.message_edit.toPlainText(),
                dest,
                priv_key,
                pub_key,
                algorithm,
            )
            self.mw.log(f"  OK — message written to {dest}")
            QMessageBox.information(self, "Success", f"Message saved to:\n{dest}")
        except Exception as e:
            self.mw.log(f"  ERROR during send: {e}")
            QMessageBox.critical(self, "Error", f"Send failed:\n{e}")


class ReceiveTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.mw = main_window
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        src_group = QGroupBox("Input File")
        src_layout = QHBoxLayout(src_group)
        self.src_edit = QLineEdit()
        self.src_edit.setReadOnly(True)
        self.src_edit.setPlaceholderText("Choose received message file...")
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_src)
        src_layout.addWidget(self.src_edit)
        src_layout.addWidget(browse_btn)
        layout.addWidget(src_group)

        keys_row = QHBoxLayout()

        sender_group = QGroupBox("Sender's Public Key (verification)")
        sender_layout = QFormLayout(sender_group)
        self.sender_key_combo = QComboBox()
        sender_layout.addRow("Key:", self.sender_key_combo)
        keys_row.addWidget(sender_group)

        recv_group = QGroupBox("My Private Key (decryption)")
        recv_layout = QFormLayout(recv_group)
        self.recv_key_combo = QComboBox()
        self.recv_password_edit = QLineEdit()
        self.recv_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.recv_password_edit.setPlaceholderText("Password for private key")
        recv_layout.addRow("Key:", self.recv_key_combo)
        recv_layout.addRow("Password:", self.recv_password_edit)
        keys_row.addWidget(recv_group)

        layout.addLayout(keys_row)

        recv_btn = QPushButton("Receive / Decrypt")
        recv_btn.setFixedHeight(40)
        recv_btn.clicked.connect(self._receive)
        layout.addWidget(recv_btn)

        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = self.status_label.font()
        font.setBold(True)
        self.status_label.setFont(font)
        layout.addWidget(self.status_label)

        msg_group = QGroupBox("Decrypted Message")
        msg_layout = QVBoxLayout(msg_group)
        self.message_display = QTextEdit()
        self.message_display.setReadOnly(True)
        msg_layout.addWidget(self.message_display)
        save_btn = QPushButton("Save Message to File")
        save_btn.clicked.connect(self._save_message)
        msg_layout.addWidget(save_btn)
        layout.addWidget(msg_group)

    def refresh_keys(self, priv_keys, pub_keys):
        self.sender_key_combo.clear()
        for k in pub_keys:
            label = f"{k['keyId']}  {k.get('name', '')} <{k.get('email', '')}>"
            self.sender_key_combo.addItem(label, k["keyId"])

        self.recv_key_combo.clear()
        for k in priv_keys:
            self.recv_key_combo.addItem(f"{k['keyId']}  ({k['keySize']} bit)", k["keyId"])

    def _browse_src(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Message File", "", "PGP files (*.pgp);;All files (*)"
        )
        if path:
            self.src_edit.setText(path)

    def _receive(self):
        user = self.mw.current_user()
        if user is None:
            QMessageBox.warning(self, "No User", "Select or create a user first.")
            return
        src = self.src_edit.text()
        if not src:
            QMessageBox.warning(self, "Error", "Choose a source file.")
            return
        if self.sender_key_combo.count() == 0:
            QMessageBox.warning(self, "Error", "No public keys available for verification.")
            return
        if self.recv_key_combo.count() == 0:
            QMessageBox.warning(self, "Error", "No private keys available for decryption.")
            return

        sender_key_id = self.sender_key_combo.currentData()
        recv_key_id = self.recv_key_combo.currentData()

        self.mw.log(f"RECEIVE  user={user.name}  src={src}")
        self.mw.log(f"  sender_key={sender_key_id}  recv_key={recv_key_id}")

        sender_pub = user.getPublicKey(sender_key_id)
        if sender_pub is None:
            self.mw.log(f"ERROR: failed to load sender public key {sender_key_id}")
            QMessageBox.critical(self, "Error", "Failed to load sender's public key.")
            return
        self.mw.log(f"  sender public key loaded  key_size={sender_pub.key_size}")

        recv_priv = user.getPrivateKey(recv_key_id, self.recv_password_edit.text().encode())
        if recv_priv is None:
            self.mw.log(f"ERROR: failed to load private key {recv_key_id} (wrong password?)")
            QMessageBox.critical(self, "Error", "Failed to load private key. Wrong password?")
            return
        self.mw.log(f"  receiver private key loaded  key_size={recv_priv.key_size}")

        pub_keys = user.loadPublicKeyRing()
        sender_info = next((k for k in pub_keys if k["keyId"] == sender_key_id), None)

        self.message_display.clear()
        self.status_label.setText("")

        try:
            message = self.mw.main_svc.receive(src, sender_pub, recv_priv)
            self.message_display.setPlainText(message)
            name = sender_info.get("name", "") if sender_info else ""
            email = sender_info.get("email", "") if sender_info else ""
            self.mw.log(f"  OK — signature verified, signed by {name} <{email}>")
            self.status_label.setStyleSheet("color: green;")
            self.status_label.setText(f"Signature verified — signed by {name} <{email}>")
        except SignatureVerificationError:
            self.mw.log(f"  FAIL — signature verification failed")
            self.status_label.setStyleSheet("color: red;")
            self.status_label.setText("Signature verification FAILED — message may be tampered")
        except Exception as e:
            self.mw.log(f"  ERROR — {e}")
            self.status_label.setStyleSheet("color: red;")
            self.status_label.setText(f"Decryption failed: {e}")

    def _save_message(self):
        text = self.message_display.toPlainText()
        if not text:
            QMessageBox.warning(self, "No Message", "No message to save.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Message", "", "Text files (*.txt);;All files (*)"
        )
        if not path:
            return
        with open(path, "w") as f:
            f.write(text)
        QMessageBox.information(self, "Saved", f"Message saved to:\n{path}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PGP Email Protection")
        self.resize(960, 780)
        self.user_svc = UserService()
        self.main_svc = MainService()

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        # User selector
        user_bar = QHBoxLayout()
        user_bar.addWidget(QLabel("Current User:"))
        self.user_combo = QComboBox()
        self.user_combo.setMinimumWidth(220)
        self.user_combo.currentIndexChanged.connect(self._on_user_changed)
        user_bar.addWidget(self.user_combo)
        new_user_btn = QPushButton("New User")
        new_user_btn.clicked.connect(self._new_user)
        user_bar.addWidget(new_user_btn)
        user_bar.addStretch()
        root.addLayout(user_bar)

        # Tabs
        self.tabs = QTabWidget()
        self.key_ring_tab = KeyRingTab(self)
        self.send_tab = SendTab(self)
        self.receive_tab = ReceiveTab(self)
        self.tabs.addTab(self.key_ring_tab, "Key Rings")
        self.tabs.addTab(self.send_tab, "Send")
        self.tabs.addTab(self.receive_tab, "Receive")
        root.addWidget(self.tabs)

        # Log panel
        log_group = QGroupBox("Log")
        log_layout = QVBoxLayout(log_group)
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setFixedHeight(130)
        self.log_edit.setStyleSheet("font-family: monospace; font-size: 11px;")
        log_layout.addWidget(self.log_edit)
        clear_btn = QPushButton("Clear Log")
        clear_btn.setFixedWidth(90)
        clear_btn.clicked.connect(self.log_edit.clear)
        log_layout.addWidget(clear_btn, alignment=Qt.AlignmentFlag.AlignRight)
        root.addWidget(log_group)

        self._load_users()

    def log(self, message: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_edit.append(f"[{ts}] {message}")

    def _load_users(self):
        self.user_combo.blockSignals(True)
        self.user_combo.clear()
        for user in self.user_svc.getUsers():
            self.user_combo.addItem(f"{user.name} <{user.email}>", user.email)
        self.user_combo.blockSignals(False)
        self._on_user_changed()

    def _on_user_changed(self):
        user = self.current_user()
        if user:
            self.log(f"Switched to user: {user.name} <{user.email}>")
        self.key_ring_tab.refresh()
        self.refresh_key_selectors()

    def _new_user(self):
        dlg = NewUserDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        name, email = dlg.get_data()
        try:
            self.user_svc.createUser(name, email)
            self.user_combo.addItem(f"{name} <{email}>", email)
            self.log(f"Created user: {name} <{email}>")
            self.user_combo.setCurrentIndex(self.user_combo.count() - 1)
        except Exception as e:
            self.log(f"ERROR creating user: {e}")
            QMessageBox.critical(self, "Error", str(e))

    def current_user(self):
        email = self.user_combo.currentData()
        if email is None:
            return None
        return self.user_svc.findUserByEmail(email)

    def refresh_key_selectors(self):
        user = self.current_user()
        if user is None:
            self.send_tab.refresh_keys([], [])
            self.receive_tab.refresh_keys([], [])
            return
        priv_keys = user.loadPrivateKeyRing()
        pub_keys = user.loadPublicKeyRing()
        self.send_tab.refresh_keys(priv_keys, pub_keys)
        self.receive_tab.refresh_keys(priv_keys, pub_keys)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
