#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QObject>
#include <QDebug>
#include <QFile>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/blowfish.h>

#define PADDING RSA_PKCS1_PADDING
#define KEYSIZE 32
#define IVSIZE 32
#define BLOCKSIZE 256
#define SALTSIZE 8

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    //----------RSA----------
    bool testRSA(const QString &filePathRSA, int choice);

    QByteArray getPublicKey();
    QByteArray getPrivateKey();

    RSA *getPublicKey(QByteArray &data);
    RSA *getPublicKey(QString filename);

    RSA *getPrivateKey(QByteArray &data);
    RSA *getPrivateKey(QString filename);

    QByteArray encryptRSA(RSA *key, QByteArray &data);
    QByteArray decryptRSA(RSA *key, QByteArray &data);

    void freeRSAKey(RSA *key);


    //----------AES----------
    bool testAES(const QString &filePathAES, const QString &password, int choice);

    QByteArray encryptAES(QByteArray passphrase, QByteArray &data);
    QByteArray decryptAES(QByteArray passphrase, QByteArray &data);

    QByteArray randomBytes(int size);


    //----------Blowfish----------
    bool testBlowfish(const QString &filePathBlowfish, const QString &password, int choice);

    QByteArray encryptBlowfish(QByteArray passphrase, QByteArray &data);
    QByteArray decryptBlowfish(QByteArray passphrase, QByteArray &data);

private slots:

    void on_encryptButton_clicked();

    void on_decryptButton_clicked();

    void on_browseButton_clicked();

    void on_passwordcheckBox_stateChanged(int arg1);

private:
    Ui::MainWindow *ui;
    QString filePath;

    void initalize();

    void finalize();

    QByteArray readFile(const QString &filePath);

    void writeFile(const QString &filePath, QByteArray &data);

};
#endif // MAINWINDOW_H
