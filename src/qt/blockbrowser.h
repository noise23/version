#ifndef BLOCKBROWSER_H
#define BLOCKBROWSER_H

#include "clientmodel.h"
#include "main.h"
#include <QDialog>

namespace Ui {
class BlockBrowser;
}
class ClientModel;

class BlockBrowser : public QDialog
{
    Q_OBJECT

public:
    explicit BlockBrowser(QWidget *parent = 0);
    ~BlockBrowser();
    
    void setTransactionId(const QString &transactionId);
    void setModel(ClientModel *model);
    
public slots:
    
    void blockClicked();
    void txClicked();
    void updateExplorer(bool);
    double getTxFees(std::string);

private slots:

private:
    Ui::BlockBrowser *ui;
    ClientModel *model;
    
};

double getTxTotalValue(std::string); 
double getMoneySupply(int64_t Height);
double convertCoins(int64_t); 
int64_t getBlockTime(int64_t); 
int64_t getBlocknBits(int64_t); 
int64_t getBlockNonce(int64_t); 
int64_t getBlockHashrate(int64_t); 
std::string getInputs(std::string); 
std::string getOutputs(std::string); 
std::string getBlockHash(int64_t); 
std::string getBlockMerkle(int64_t); 
bool addnode(std::string); 
const CBlockIndex* getBlockIndex(int64_t);

#endif // BLOCKBROWSER_H
