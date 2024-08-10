#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFileDialog>
#include <QTextStream>
#include <QLineEdit>
#include <QCheckBox>
#include <iostream>
#include <fstream>
#include <cstring>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    initalize();
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    finalize();
    delete ui;
}

void MainWindow::on_encryptButton_clicked()
{
    filePath = ui->filepathEdit->text();
    if (!filePath.isEmpty()) {
        if (ui->rsaButton->isChecked()) {
            if (!ui->passwordEdit->text().isEmpty()) {
                QFileInfo fileInfo(filePath);
                QString directoryPath = fileInfo.path();
                if (testRSA(filePath, 1)) {
                    QMessageBox::information(this, "Message", "<html><b>Encrypted and Saved</b> at Location: <a href='file://" + directoryPath + "'>" + directoryPath + "</a></html>");
                }
                else {
                    QMessageBox::warning(this, "Error", "<html><b>Encryption Failed !</b></html>");
                }
            }
            else {
                QMessageBox::warning(this, "Error", "Please enter the Password.");
            }

        }
        else if (ui->aesButton->isChecked()) {
            if (!ui->passwordEdit->text().isEmpty()) {
                QFileInfo fileInfo(filePath);
                QString directoryPath = fileInfo.path();
                QString password = ui->passwordEdit->text();
                if (testAES(filePath, password, 1)) {
                    QMessageBox::information(this, "Message", "<html><b>Encrypted and Saved</b> at Location: <a href='file://" + directoryPath + "'>" + directoryPath + "</a></html>");
                }
                else {
                    QMessageBox::warning(this, "Error", "<html><b>Encryption Failed !</b></html>");
                }

            }
            else {
                QMessageBox::warning(this, "Error", "Please enter the Password.");
            }
        }
        else if (ui->blowfishButton->isChecked()) {
            if (!ui->passwordEdit->text().isEmpty()) {
                QFileInfo fileInfo(filePath);
                QString directoryPath = fileInfo.path();
                QString password = ui->passwordEdit->text();
                if (testBlowfish(filePath, password, 1)) {
                    QMessageBox::information(this, "Message", "<html><b>Encrypted and Saved</b> at Location: <a href='file://" + directoryPath + "'>" + directoryPath + "</a></html>");
                }
                else {
                    QMessageBox::warning(this, "Error", "<html><b>Encryption Failed !</b></html>");
                }
            }
            else {
                QMessageBox::warning(this, "Error", "Please enter the Password.");
            }
        }
        else {
            QMessageBox::warning(this, "Error", "Please select any Encryption algorithm.");
        }
    } else {
        QMessageBox::warning(this, "Error", "Please select a file first.");
    }
}

void MainWindow::on_decryptButton_clicked()
{
    filePath = ui->filepathEdit->text();
    if (!filePath.isEmpty()) {
        if (ui->rsaButton->isChecked()) {
            if (!ui->passwordEdit->text().isEmpty()) {
                QFileInfo fileInfo(filePath);
                QString directoryPath = fileInfo.path();
                if (testRSA(filePath, 2)) {
                    QMessageBox::information(this, "Message", "<html><b>Decrypted and Saved</b> at Location: <a href='file://" + directoryPath + "'>" + directoryPath + "</a></html>");
                }
                else {
                    QMessageBox::warning(this, "Error", "<html><b>Decryption Failed !</b></html>");
                }
            }
            else {
                QMessageBox::warning(this, "Error", "Please enter the Password.");
            }
        }
        else if (ui->aesButton->isChecked()) {
            if (!ui->passwordEdit->text().isEmpty()) {

                QFileInfo fileInfo(filePath);
                QString directoryPath = fileInfo.path();
                QString password = ui->passwordEdit->text();
                if (testAES(filePath, password, 2)) {
                    QMessageBox::information(this, "Message", "<html><b>Decrypted and Saved</b> at Location: <a href='file://" + directoryPath + "'>" + directoryPath + "</a></html>");
                }
                else {
                    QMessageBox::warning(this, "Error", "<html><b>Decryption Failed !</b></html>");
                }
            }
            else {
                QMessageBox::warning(this, "Error", "Please enter the Password.");
            }
        }
        else if (ui->blowfishButton->isChecked()) {
            if (!ui->passwordEdit->text().isEmpty()) {
                QFileInfo fileInfo(filePath);
                QString directoryPath = fileInfo.path();
                QString password = ui->passwordEdit->text();
                if (testBlowfish(filePath, password, 2)) {
                    QMessageBox::information(this, "Message", "<html><b>Decrypted and Saved</b> at Location: <a href='file://" + directoryPath + "'>" + directoryPath + "</a></html>");
                }
                else {
                    QMessageBox::warning(this, "Error", "<html><b>Decryption Failed !</b></html>");
                }
            }
            else {
                QMessageBox::warning(this, "Error", "Please enter the Password.");
            }
        }
        else {
            QMessageBox::warning(this, "Error", "Please select any Decryption algorithm.");
        }

    } else {
        QMessageBox::warning(this, "Error", "Please select a file first.");
    }
}

void MainWindow::on_browseButton_clicked()
{
    filePath = QFileDialog::getOpenFileName(this, "Choose a file", QDir::homePath());
    ui->filepathEdit->setText(filePath);
}

void MainWindow::on_passwordcheckBox_stateChanged(int arg1)
{
    if (arg1 == Qt::Checked) {
        ui->passwordEdit->setEchoMode(QLineEdit::Normal);
    } else {
        ui->passwordEdit->setEchoMode(QLineEdit::Password);
    }
}


//----------RSA----------

bool MainWindow::testRSA(const QString &filePathRSA, int choice)
{
    qDebug() << "Loading keys...";
    try {
        if (choice == 1) {
            QByteArray testPublicKey = getPublicKey();
            RSA* publickey = getPublicKey(testPublicKey);
            QByteArray plain = readFile(filePathRSA);
            qDebug() << plain;
            QByteArray encrypted = encryptRSA(publickey, plain);
            qDebug() << encrypted.toBase64();
            writeFile(filePathRSA, encrypted);
            freeRSAKey(publickey);
            return true;
        }
        else if (choice == 2) {
            QByteArray testPrivateKey = getPrivateKey();
            RSA* privatekey = getPrivateKey(testPrivateKey);
            QByteArray encrypted = readFile(filePathRSA);
            qDebug() << encrypted.toBase64();
            QByteArray decrypted = decryptRSA(privatekey, encrypted);
            qDebug() << decrypted;
            writeFile(filePathRSA, decrypted);
            freeRSAKey(privatekey);
            return true;
        }
        else {
            return false;
        }
    } catch (const std::exception &ex) {
        // Handle the exception here, e.g., display an error message
        qDebug() << "Error: " << ex.what();
        QMessageBox::warning(this, "Error", ex.what());
        return false;
    }
}

QByteArray MainWindow::getPublicKey()
{
    QByteArray testPublicKey;

    testPublicKey.append("-----BEGIN PUBLIC KEY-----\n");
    testPublicKey.append("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnqXlIdgpIW6o05RJkxpc\n");
    testPublicKey.append("YpHPQVNpwD/BBpUpWylj72gKSDYU+bfBYFrKNEFfaXmwGhp5lCwaktcYaEl4jL0a\n");
    testPublicKey.append("jd8sZrIY+AnQ7iKLSpz4kjz5DOwtWIhrd1HW9iaJqzOO8ooEmtuih4g/V/NZEI7S\n");
    testPublicKey.append("1BOEDKWUaA2sq5DsXMYA9VJ+tQwauHDmLn8WAf9bZLbGL1ydSbI5bT555sLnmb1D\n");
    testPublicKey.append("noCOxO/I+yDx0ETnv+e0A4WQLvFxh/DwQiqV8TDU0Ve1EX7pjQ0e89rtBxyfmyeS\n");
    testPublicKey.append("DXnlyRNKSEq7XEVb2fz8NEHuMzwDQKGEHagpCL4i7NkZwYMvyTPooQSk5ekE2/M2\n");
    testPublicKey.append("gwIDAQAB\n");
    testPublicKey.append("-----END PUBLIC KEY-----");

    return testPublicKey;
}

QByteArray MainWindow::getPrivateKey()
{
    QByteArray testPrivateKey;

    testPrivateKey.append("-----BEGIN RSA PRIVATE KEY-----\n");
    testPrivateKey.append("MIIEowIBAAKCAQEAnqXlIdgpIW6o05RJkxpcYpHPQVNpwD/BBpUpWylj72gKSDYU\n");
    testPrivateKey.append("+bfBYFrKNEFfaXmwGhp5lCwaktcYaEl4jL0ajd8sZrIY+AnQ7iKLSpz4kjz5DOwt\n");
    testPrivateKey.append("WIhrd1HW9iaJqzOO8ooEmtuih4g/V/NZEI7S1BOEDKWUaA2sq5DsXMYA9VJ+tQwa\n");
    testPrivateKey.append("uHDmLn8WAf9bZLbGL1ydSbI5bT555sLnmb1DnoCOxO/I+yDx0ETnv+e0A4WQLvFx\n");
    testPrivateKey.append("h/DwQiqV8TDU0Ve1EX7pjQ0e89rtBxyfmyeSDXnlyRNKSEq7XEVb2fz8NEHuMzwD\n");
    testPrivateKey.append("QKGEHagpCL4i7NkZwYMvyTPooQSk5ekE2/M2gwIDAQABAoIBAHKs369THIf6ATbO\n");
    testPrivateKey.append("3U/johvt4a4KqUo5y0EC2N34UTBgN+5yiT7oQHNxrO+QwXLwbwavVGpyZtL1f8MC\n");
    testPrivateKey.append("OI0is+sRAntJCRthnRBFEAJi7JpoUG2y2iRAl82r7oIG4URLBGz0rtdxI05sgb0F\n");
    testPrivateKey.append("Pb/mPSbm5HBvz5JXMBTjsLZuuYqZb2Foyqh8V8hOTFBlM+IE4V1m+3S3tIxhTLQO\n");
    testPrivateKey.append("jLzN3t8l0+dBZaJrvYodCrXxJtAU2iLcmlNS2v1k5fy1kNbUzb9dBOgAmhDKrpq5\n");
    testPrivateKey.append("tXkzxvMrAmE3vlHn/N/FMvdjlbnOYq9Gi/YW72SwW/QEWfyRArVys0MlfZJk58Uk\n");
    testPrivateKey.append("wwgMfiECgYEAzw9+/bvwMKk7wOyvm3Wt/rwhqUBjEIwfa+yirws8HbQhLNuqUQUt\n");
    testPrivateKey.append("tlt8Dy0y+MMPZWEqEgZHKsqgyXR8/GO72pq8CaaEM1d/Iv1LajjL4gOQmeNRjJYf\n");
    testPrivateKey.append("K+hX7/9tEuuArqFBdgJGPZ8BcaCbj/HCL8RhkVysqd5KiVHhBHuoSwcCgYEAxCUg\n");
    testPrivateKey.append("96Bx7BOB83M/QU+Axg3p3dEMA1pxV2ZXHyO6bsGk3KRPD7UB/wz4SfoTO7AyfybN\n");
    testPrivateKey.append("B7O9zAlyprcMAmIJCIxy6j/Hnhv/csQwnwGvGoEBdHhCci6PAE/h0fyjFCnBuKIe\n");
    testPrivateKey.append("i/b8amw8UXwQQSMbPbzyBClBOgF3G4uptf2YjaUCgYEAvv3ZMmy/sfL4Rg1MMgaL\n");
    testPrivateKey.append("dxPLrNXSSvolJaTBrtqbGf8ENt9sK42uS635MfqMML+kHOxSJQwbaxI623gSra/F\n");
    testPrivateKey.append("IHBoEDLDcKQ9hmXDwXggQBrvr7LpjtcOa67GJn8h+ji2mt3ths+0QLTBXTE7LLxg\n");
    testPrivateKey.append("VTU8lhu4vHtpn16iQ0NYydMCgYArryk8fVth/KZAljZMUWyYr5iacmh+hrIfiQd2\n");
    testPrivateKey.append("Q/rNmAsjqOSC1wluyHCz6SJHdOKKNxYK1Rk8TA5g2vutvC/O25jsWvAWYp3t7Yv2\n");
    testPrivateKey.append("neVlvb2ZNv91drEanK/qmJ2pa/NdL54mBggJm7mDXGIyX6M9iMtN6fJA/PqOA/j0\n");
    testPrivateKey.append("M1q6kQKBgFrA3KS3YSL4rCnOU1WVpf1Reaz6abzgNMn5yufqoHUfO3fTnlHgLegh\n");
    testPrivateKey.append("dPXD3IdqzQe09sFfRSPPzRIUPL1ilziqNgPvgAmDoAN/UuVuvag3tB9b4UUPMgwv\n");
    testPrivateKey.append("eQO9pJJ1bO26g1nFDX3mIkYSrgZNxbmwL0A4c4nCqiS2ehzeAbm5\n");
    testPrivateKey.append("-----END RSA PRIVATE KEY-----");

    return testPrivateKey;
}

RSA *MainWindow::getPublicKey(QByteArray &data)
{
    const char* publicKeyStr = data.constData();
    BIO* bio = BIO_new_mem_buf((void*)publicKeyStr, -1);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    RSA* rsaPubKey = PEM_read_bio_RSA_PUBKEY(bio,NULL, NULL, NULL);
    if(!rsaPubKey)
    {
        QString errorMessage = "Could not load Public key: " + QString(ERR_error_string(ERR_get_error(), NULL));
        throw std::runtime_error(errorMessage.toStdString());
    }

    BIO_free(bio);
    return rsaPubKey;
}

RSA *MainWindow::getPublicKey(QString filename)
{
    QByteArray data = readFile(filename);

    return getPublicKey(data);
}

RSA *MainWindow::getPrivateKey(QByteArray &data)
{
    const char* privateKeyStr = data.constData();
    BIO* bio = BIO_new_mem_buf((void*)privateKeyStr, -1);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    RSA* rsaPrivKey = PEM_read_bio_RSAPrivateKey(bio,NULL, NULL, NULL);
    if(!rsaPrivKey)
    {
        QString errorMessage = "Could not load Private key: " + QString(ERR_error_string(ERR_get_error(), NULL));
        throw std::runtime_error(errorMessage.toStdString());
    }

    BIO_free(bio);
    return rsaPrivKey;
}

RSA *MainWindow::getPrivateKey(QString filename)
{
    QByteArray data = readFile(filename);

    return getPrivateKey(data);
}

QByteArray MainWindow::encryptRSA(RSA *key, QByteArray &data)
{
    QByteArray buffer;
    int dataSize = data.length();
    const unsigned char* str = (const unsigned char*)data.constData();
    int rsaLen = RSA_size(key);

    unsigned char* ed = (unsigned char*)malloc(rsaLen);
    // RSA_private_encrypt() - if you are encrypting with the private key
    int resultLen = RSA_public_encrypt(dataSize, (const unsigned char*)str, ed, key, PADDING);

    if (resultLen == -1)
    {
        QString errorMessage = "Could not encrypt: " + QString(ERR_error_string(ERR_get_error(), NULL));
        throw std::runtime_error(errorMessage.toStdString());
    }

    buffer = QByteArray(reinterpret_cast<char*>(ed), resultLen);

    return buffer;
}

QByteArray MainWindow::decryptRSA(RSA *key, QByteArray &data)
{
    QByteArray buffer;
    const unsigned char* encryptedData = (const unsigned char*)data.constData();

    int rsaLen = RSA_size(key);

    unsigned char* ed = (unsigned char*)malloc(rsaLen);
    // RSA_public_decrypt() - if you are using the public key
    int resultLen = RSA_private_decrypt(rsaLen, encryptedData, ed, key, PADDING);

    if (resultLen == -1)
    {
        QString errorMessage = "Could not decrypt: " + QString(ERR_error_string(ERR_get_error(), NULL));
        throw std::runtime_error(errorMessage.toStdString());
    }

    buffer = QByteArray::fromRawData((const char*)ed, resultLen);
    return buffer;
}

void MainWindow::freeRSAKey(RSA *key)
{
    RSA_free(key);
}


//----------AES----------

bool MainWindow::testAES(const QString &filePathAES, const QString &password, int choice)
{
    qDebug() << "Testing AES...";
    try {
        if (choice == 1) {
            QByteArray plain = readFile(filePathAES);
            qDebug() << plain;
            QByteArray encrypted = encryptAES(password.toLatin1(), plain);
            qDebug() << encrypted.toBase64();
            writeFile(filePathAES, encrypted);
            return true;
        } else if (choice == 2) {
            QByteArray encrypted = readFile(filePathAES);
            qDebug() << encrypted.toBase64();
            QByteArray decrypted = decryptAES(password.toLatin1(), encrypted);
            qDebug() << decrypted;
            writeFile(filePathAES, decrypted);
            return true;
        } else {
            return false;
        }
    } catch (const std::exception &ex) {
        // Handle the exception here, e.g., display an error message
        qDebug() << "Error: " << ex.what();
        QMessageBox::warning(this, "Error", ex.what());
        return false;
    }
}

QByteArray MainWindow::encryptAES(QByteArray passphrase, QByteArray &data)
{
    QByteArray msalt = randomBytes(SALTSIZE);
    int rounds = 1;
    unsigned char key[KEYSIZE];
    unsigned char iv[IVSIZE];

    const unsigned char* salt = (const unsigned char*)msalt.constData();
    const unsigned char* password = (const unsigned char*)passphrase.constData();

    int i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, password, passphrase.length(), rounds, key, iv);

    if (i != KEYSIZE)
    {
        QString errorMessage = "EVP_BytesToKey() error: " + QString(ERR_error_string(ERR_get_error(), NULL));
        throw std::runtime_error(errorMessage.toStdString());
    }

    EVP_CIPHER_CTX *en = EVP_CIPHER_CTX_new();

    if (!en)
    {
        throw std::runtime_error("EVP_CIPHER_CTX_new() failed");
    }

    if (!EVP_EncryptInit_ex(en, EVP_aes_256_cbc(), NULL, key, iv))
    {
        QString errorMessage = "EVP_EncryptInit_ex() failed " + QString(ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_free(en);
        throw std::runtime_error(errorMessage.toStdString());
    }

    char *input = data.data();
    int len = data.size();

    int c_len = len + AES_BLOCK_SIZE, f_len = 0;
    unsigned char *ciphertext = (unsigned char*)malloc(c_len);

    if (!EVP_EncryptUpdate(en, ciphertext, &c_len, (unsigned char *)input, len))
    {
        QString errorMessage = "EVP_EncryptUpdate() failed " + QString(ERR_error_string(ERR_get_error(), NULL));
        free(ciphertext);
        EVP_CIPHER_CTX_free(en);
        throw std::runtime_error(errorMessage.toStdString());
    }

    if (!EVP_EncryptFinal_ex(en, ciphertext + c_len, &f_len))
    {
        QString errorMessage = "EVP_EncryptFinal_ex() failed " + QString(ERR_error_string(ERR_get_error(), NULL));
        free(ciphertext);
        EVP_CIPHER_CTX_free(en);
        throw std::runtime_error(errorMessage.toStdString());
    }

    len = c_len + f_len;

    QByteArray encrypted = QByteArray(reinterpret_cast<char*>(ciphertext), len);
    QByteArray finished;
    finished.append("Salted__");
    finished.append(msalt);
    finished.append(encrypted);

    free(ciphertext);
    EVP_CIPHER_CTX_free(en);

    return finished;
}

QByteArray MainWindow::decryptAES(QByteArray passphrase, QByteArray &data)
{
    QByteArray msalt;
    if (QString(data.mid(0, 8)) == "Salted__")
    {
        msalt = data.mid(8, 8);
        data = data.mid(16);
    }
    else
    {
        qWarning() << "Could not load salt from data!";
        QMessageBox::warning(this, "Error", "Could not load salt from data!");
        msalt = randomBytes(SALTSIZE);
    }

    int rounds = 1;
    unsigned char key[KEYSIZE];
    unsigned char iv[IVSIZE];
    const unsigned char* salt = (const unsigned char*)msalt.constData();
    const unsigned char* password = (const unsigned char*)passphrase.data();

    int i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, password, passphrase.length(), rounds, key, iv);

    if (i != KEYSIZE)
    {
        QString errorMessage = "EVP_BytesToKey() error: " + QString(ERR_error_string(ERR_get_error(), NULL));
        throw std::runtime_error(errorMessage.toStdString());
    }

    EVP_CIPHER_CTX *de = EVP_CIPHER_CTX_new();

    if (!de)
    {
        throw std::runtime_error("EVP_CIPHER_CTX_new() failed");
    }

    if (!EVP_DecryptInit_ex(de, EVP_aes_256_cbc(), NULL, key, iv))
    {
        QString errorMessage = "EVP_DecryptInit_ex() failed: " + QString(ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_free(de);
        throw std::runtime_error(errorMessage.toStdString());
    }

    char *input = data.data();
    int len = data.size();

    int p_len = len, f_len = 0;
    unsigned char *plaintext = (unsigned char *)malloc(p_len + AES_BLOCK_SIZE);

    // May have to do this multiple times for large data
    if (!EVP_DecryptUpdate(de, plaintext, &p_len, (unsigned char *)input, len))
    {
        QString errorMessage = "EVP_DecryptUpdate() failed: " + QString(ERR_error_string(ERR_get_error(), NULL));
        free(plaintext);
        EVP_CIPHER_CTX_free(de);
        throw std::runtime_error(errorMessage.toStdString());
    }

    if (!EVP_DecryptFinal_ex(de, plaintext + p_len, &f_len))
    {
        QString errorMessage = "EVP_DecryptFinal_ex() failed: " + QString(ERR_error_string(ERR_get_error(), NULL));
        free(plaintext);
        EVP_CIPHER_CTX_free(de);
        throw std::runtime_error(errorMessage.toStdString());
    }

    len = p_len + f_len;

    EVP_CIPHER_CTX_free(de);

    QByteArray decrypted = QByteArray(reinterpret_cast<char*>(plaintext), len);
    free(plaintext);

    return decrypted;
}

QByteArray MainWindow::randomBytes(int size)
{
    unsigned char arr[size];
    RAND_bytes(arr,size);

    QByteArray buffer = QByteArray(reinterpret_cast<char*>(arr), size);
    return buffer;
}

void MainWindow::initalize()
{
    ERR_load_CRYPTO_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
}

void MainWindow::finalize()
{
    EVP_cleanup();
    ERR_free_strings();
}

QByteArray MainWindow::readFile(const QString &filePath)
{
    QByteArray data;
    QFile file(filePath);
    if (!file.open(QFile::ReadOnly))
    {
        throw std::runtime_error(file.errorString().toStdString()); // Throw a std::runtime_error with the error message.
    }

    data = file.readAll();
    file.close();
    return data;
}

void MainWindow::writeFile(const QString &filePath, QByteArray &data)
{
    QFile file(filePath);
    if (!file.open(QFile::WriteOnly))
    {
        throw std::runtime_error(file.errorString().toStdString()); // Throw a std::runtime_error with the error message.
    }

    qint64 bytesWritten = file.write(data);
    file.close();

    if (bytesWritten == -1 || bytesWritten != data.size())
    {
        throw std::runtime_error("Error writing data to file.");
    }
}


//----------Blowfish----------

bool MainWindow::testBlowfish(const QString &filePathBlowfish, const QString &password, int choice)
{
    qDebug() << "Testing Blowfish...";
    try {
        if (choice == 1) {
            QByteArray plain = readFile(filePathBlowfish);
            qDebug() << plain;
            QByteArray encrypted = encryptBlowfish(password.toLatin1(), plain);
            qDebug() << encrypted.toBase64();
            writeFile(filePathBlowfish, encrypted);
            return true;
        } else if (choice == 2) {
            QByteArray encrypted = readFile(filePathBlowfish);
            qDebug() << encrypted.toBase64();
            QByteArray decrypted = decryptBlowfish(password.toLatin1(), encrypted);
            qDebug() << decrypted;
            writeFile(filePathBlowfish, decrypted);
            return true;
        } else {
            return false;
        }
    } catch (const std::exception &ex) {
        // Handle the exception here, e.g., display an error message
        qDebug() << "Error: " << ex.what();
        QMessageBox::warning(this, "Error", ex.what());
        return false;
    }
}

QByteArray MainWindow::encryptBlowfish(QByteArray passphrase, QByteArray &data)
{
    // Generate a random initialization vector (IV)
    unsigned char iv[8];
    RAND_bytes(iv, sizeof(iv));

    // Set up the encryption context
    BF_KEY bfKey;
    BF_set_key(&bfKey, passphrase.length(), (const unsigned char*)passphrase.constData());

    // Initialize the IV
    unsigned char ivec[8];
    memcpy(ivec, iv, sizeof(ivec));

    // Perform Blowfish encryption
    unsigned char *input = (unsigned char *)data.constData();
    int len = data.size();
    unsigned char *ciphertext = (unsigned char *)malloc(len);

    // Decrypt the data using Blowfish CFB mode
    int num = 0; // Initialize num to 0
    BF_cfb64_encrypt(input, ciphertext, len, &bfKey, ivec, &num, BF_ENCRYPT);

    QByteArray encrypted;
    encrypted.append((const char*)iv, sizeof(iv));
    encrypted.append((char*)ciphertext, len);

    free(ciphertext);

    return encrypted;
}

QByteArray MainWindow::decryptBlowfish(QByteArray passphrase, QByteArray &data)
{
    // Extract the IV from the data
    unsigned char iv[8];
    if (data.size() < sizeof(iv)) {
        // Handle error, insufficient data
        throw std::runtime_error("Insufficient data for IV");
    }
    memcpy(iv, data.constData(), sizeof(iv));

    // Set up the decryption context
    BF_KEY bfKey;
    BF_set_key(&bfKey, passphrase.length(), (const unsigned char*)passphrase.constData());

    // Initialize the IV
    unsigned char ivec[8];
    memcpy(ivec, iv, sizeof(ivec));

    // Perform Blowfish decryption
    unsigned char *input = (unsigned char *)data.constData() + sizeof(iv);
    int len = data.size() - sizeof(iv);
    unsigned char *plaintext = (unsigned char *)malloc(len);

    // Decrypt the data using Blowfish CFB mode
    int num = 0; // Initialize num to 0
    BF_cfb64_encrypt(input, plaintext, len, &bfKey, ivec, &num, BF_DECRYPT);

    QByteArray decrypted;
    decrypted.append((char*)plaintext, len); // Append all bytes, including padding

    free(plaintext);

    return decrypted;
}
