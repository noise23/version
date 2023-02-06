/*
 * Qt4 version GUI.
 *
 * W.J. van der Laan 2011-2012
 * The Bitcoin Developers 2011-2012
 * The Version Developers 2013-2018
 */
#include "bitcoingui.h"
#include "transactiontablemodel.h"
#include "addressbookpage.h"
#include "sendcoinsdialog.h"
#include "messagepage.h"
#include "verifymessagedialog.h"
#include "optionsdialog.h"
#include "aboutdialog.h"
#include "clientmodel.h"
#include "walletmodel.h"
#include "editaddressdialog.h"
#include "optionsmodel.h"
#include "transactiondescdialog.h"
#include "addresstablemodel.h"
#include "transactionview.h"
#include "overviewpage.h"
#include "bitcoinunits.h"
#include "guiconstants.h"
#include "askpassphrasedialog.h"
#include "notificator.h"
#include "guiutil.h"
#include "rpcconsole.h"
#include "ui_interface.h"
#include "wallet.h"
#include "blockbrowser.h"

#ifdef Q_OS_MAC
#include "macdockiconhandler.h"
#endif

#include <QDebug>
#include <QApplication>
#include <QMainWindow>
#include <QMenuBar>
#include <QMenu>
#include <QIcon>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QToolBar>
#include <QStatusBar>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QLocale>
#include <QMessageBox>
#include <QProgressBar>
#include <QStackedWidget>
#include <QDateTime>
#include <QMovie>
#include <QFileDialog>
#if QT_VERSION < 0x050000
#include <QDesktopServices>
#else
#include <QStandardPaths>
#endif
#include <QTimer>
#if QT_VERSION < 0x050000
#include <QUrl>
#endif
#include <QMimeData>

#include <QDragEnterEvent>
#include <QUrl>

#include <iostream>

extern CWallet* pwalletMain;
extern int64_t nLastCoinStakeSearchInterval;
extern int nStakeTargetSpacing;
double GetPoSKernelPS(const CBlockIndex* blockindex = NULL);

BitcoinGUI::BitcoinGUI(QWidget *parent):
    QMainWindow(parent),
    clientModel(0),
    walletModel(0),
    encryptWalletAction(0),
    unlockWalletforposAction(0),
    unlockWalletAction(0),
    lockWalletAction(0),
    changePassphraseAction(0),
    aboutQtAction(0),
    trayIcon(0),
    notificator(0),
    rpcConsole(0),
    blockBrowser(0)
{
    updateStyle();
    resize(850, 550);
    setWindowTitle(tr("Version [V] Personal Vault ") + QString::fromStdString(FormatFullVersion()));
#ifndef Q_OS_MAC
    setWindowIcon(QIcon(":icons/version"));
#else
    setUnifiedTitleAndToolBarOnMac(true);
    QApplication::setAttribute(Qt::AA_DontShowIconsInMenus);
#endif


    // Accept D&D of URIs
    setAcceptDrops(true);

    // Create actions for the toolbar, menu bar and tray/dock icon
    createActions();

    // Create application menu bar
    createMenuBar();

    // Create the toolbars
    createToolBars();

    // Create the tray icon (or setup the dock icon)
    createTrayIcon();

    // Create tabs
    overviewPage = new OverviewPage();
    blockBrowser = new BlockBrowser(this);

    transactionsPage = new QWidget(this);
    QVBoxLayout *vbox = new QVBoxLayout();
    transactionView = new TransactionView(this);
    vbox->addWidget(transactionView);
    transactionsPage->setLayout(vbox);

    addressBookPage = new AddressBookPage(AddressBookPage::ForEditing, AddressBookPage::SendingTab);

    receiveCoinsPage = new AddressBookPage(AddressBookPage::ForEditing, AddressBookPage::ReceivingTab);

    sendCoinsPage = new SendCoinsDialog(this);

    messagePage = new MessagePage(this);

    centralWidget = new QStackedWidget(this);
    centralWidget->addWidget(overviewPage);
    centralWidget->addWidget(transactionsPage);
    centralWidget->addWidget(addressBookPage);
    centralWidget->addWidget(receiveCoinsPage);
    centralWidget->addWidget(sendCoinsPage);
    centralWidget->addWidget(blockBrowser);
#ifdef FIRST_CLASS_MESSAGING
    centralWidget->addWidget(messagePage);
#endif
    setCentralWidget(centralWidget);

    // Create status bar
    statusBar();

    // Status bar notification icons
    QFrame *frameBlocks = new QFrame();
    frameBlocks->setContentsMargins(0,0,0,0);
    frameBlocks->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Preferred);
    QHBoxLayout *frameBlocksLayout = new QHBoxLayout(frameBlocks);
    frameBlocksLayout->setContentsMargins(3,0,3,0);
    frameBlocksLayout->setSpacing(3);
    labelEncryptionIcon = new QLabel();
	labelStakingIcon = new QLabel();
    labelConnectionsIcon = new QLabel();
    labelBlocksIcon = new QLabel();
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(labelEncryptionIcon);
    frameBlocksLayout->addStretch();
	frameBlocksLayout->addWidget(labelStakingIcon);
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(labelConnectionsIcon);
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(labelBlocksIcon);
    frameBlocksLayout->addStretch();
	
	QTimer *timerStakingIcon = new QTimer(labelStakingIcon);
    connect(timerStakingIcon, SIGNAL(timeout()), this, SLOT(updateStakingIcon()));
    timerStakingIcon->start(30 * 1000);
    updateStakingIcon();

    // Progress bar and label for blocks download
    progressBarLabel = new QLabel();
    progressBarLabel->setVisible(false);
    progressBar = new QProgressBar();
    progressBar->setAlignment(Qt::AlignCenter);
    progressBar->setVisible(false);

    statusBar()->addWidget(progressBarLabel);
    statusBar()->addWidget(progressBar);
    statusBar()->addPermanentWidget(frameBlocks);

    syncIconMovie = new QMovie(":/movies/update_spinner", "mng", this);

    // Clicking on a transaction on the overview page simply sends you to transaction history page
    connect(overviewPage, SIGNAL(transactionClicked(QModelIndex)), this, SLOT(gotoHistoryPage()));

    // Doubleclicking on a transaction on the transaction history page shows details
    connect(transactionView, SIGNAL(doubleClicked(QModelIndex)), transactionView, SLOT(showDetails()));

    rpcConsole = new RPCConsole(this);
    connect(openRPCConsoleAction, SIGNAL(triggered()), rpcConsole, SLOT(show()));
	
	blockBrowser = new BlockBrowser(this);
    connect(blockAction, SIGNAL(triggered()), blockBrowser, SLOT(show()));
	
    // Clicking on "Block Explorer" in the transaction page sends you to the blockbrowser
    connect(transactionView, SIGNAL(blockBrowserSignal(QString)), this, SLOT(gotoBlockBrowser(QString)));

    gotoOverviewPage();
}

BitcoinGUI::~BitcoinGUI()
{
#ifdef Q_OS_MAC
    delete appMenuBar;
#endif
}

void BitcoinGUI::createActions()
{
    QActionGroup *tabGroup = new QActionGroup(this);

    overviewAction = new QAction(QIcon(":/icons/overview"), tr("&Vault Dashboard"), this);
    overviewAction->setToolTip(tr("Show general overview of wallet"));
    overviewAction->setCheckable(true);
    overviewAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_1));
    tabGroup->addAction(overviewAction);

    historyAction = new QAction(QIcon(":/icons/history"), tr("&Ledger"), this);
    historyAction->setToolTip(tr("Browse transaction history"));
    historyAction->setCheckable(true);
    historyAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_4));
    tabGroup->addAction(historyAction);

    addressBookAction = new QAction(QIcon(":/icons/address-book"), tr("&Black Book"), this);
    addressBookAction->setToolTip(tr("Edit the list of stored addresses and labels"));
    addressBookAction->setCheckable(true);
    addressBookAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_5));
    tabGroup->addAction(addressBookAction);

    receiveCoinsAction = new QAction(QIcon(":/icons/receiving_addresses"), tr("&Receive [V] Crypto"), this);
    receiveCoinsAction->setToolTip(tr("Show the list of addresses for receiving payments"));
    receiveCoinsAction->setCheckable(true);
    receiveCoinsAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_3));
    tabGroup->addAction(receiveCoinsAction);

    sendCoinsAction = new QAction(QIcon(":/icons/send"), tr("&Transfer [V] Crypto"), this);
    sendCoinsAction->setToolTip(tr("Send coins to a version address"));
    sendCoinsAction->setCheckable(true);
    sendCoinsAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_2));
    tabGroup->addAction(sendCoinsAction);

    messageAction = new QAction(QIcon(":/icons/edit"), tr("Sign &message"), this);
    messageAction->setToolTip(tr("Prove you control an address"));
#ifdef FIRST_CLASS_MESSAGING
    messageAction->setCheckable(true);
#endif
    tabGroup->addAction(messageAction);

    connect(overviewAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(overviewAction, SIGNAL(triggered()), this, SLOT(gotoOverviewPage()));
    connect(historyAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(historyAction, SIGNAL(triggered()), this, SLOT(gotoHistoryPage()));
    connect(addressBookAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(addressBookAction, SIGNAL(triggered()), this, SLOT(gotoAddressBookPage()));
    connect(receiveCoinsAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(receiveCoinsAction, SIGNAL(triggered()), this, SLOT(gotoReceiveCoinsPage()));
    connect(sendCoinsAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(sendCoinsAction, SIGNAL(triggered()), this, SLOT(gotoSendCoinsPage()));
    connect(messageAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(messageAction, SIGNAL(triggered()), this, SLOT(gotoMessagePage()));

    quitAction = new QAction(QIcon(":/icons/quit"), tr("E&xit"), this);
    quitAction->setToolTip(tr("Quit application"));
    quitAction->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_Q));
    quitAction->setMenuRole(QAction::QuitRole);
    aboutAction = new QAction(QIcon(":/icons/version"), tr("&About %1").arg(qApp->applicationName()), this);
    aboutAction->setToolTip(tr("Show information about Version"));
    aboutAction->setMenuRole(QAction::AboutRole);
    aboutQtAction = new QAction(tr("About &Qt"), this);
    aboutQtAction->setToolTip(tr("Show information about Qt"));
    aboutQtAction->setMenuRole(QAction::AboutQtRole);
    optionsAction = new QAction(QIcon(":/icons/options"), tr("&Options..."), this);
    optionsAction->setToolTip(tr("Modify configuration options for version"));
    optionsAction->setMenuRole(QAction::PreferencesRole);
    toggleHideAction = new QAction(QIcon(":/icons/version"), tr("Show/Hide &Version"), this);
    toggleHideAction->setToolTip(tr("Show or hide the Version window"));
    exportAction = new QAction(QIcon(":/icons/export"), tr("&Export..."), this);
    exportAction->setToolTip(tr("Export the data in the current tab to a file"));
    encryptWalletAction = new QAction(QIcon(":/icons/lock_closed"), tr("&Encrypt Vault"), this);
    encryptWalletAction->setToolTip(tr("Encrypt or decrypt vault"));
    encryptWalletAction->setCheckable(true);
	
    unlockWalletforposAction = new QAction(QIcon(":/icons/lock_open"), tr("&Unlock Vault For PoS..."), this);
    unlockWalletforposAction->setStatusTip(tr("Unlock the vault for PoS"));
    unlockWalletforposAction->setCheckable(true);
    unlockWalletAction = new QAction(QIcon(":/icons/lock_open"), tr("&Unlock Vault..."), this);
    unlockWalletAction->setStatusTip(tr("Unlock the vault"));
    unlockWalletAction->setCheckable(true);

    lockWalletAction = new QAction(QIcon(":/icons/lock_closed"), tr("&Lock Vault..."), this);
    lockWalletAction->setStatusTip(tr("Lock the vault"));
    lockWalletAction->setCheckable(true);
	
    stakeMinerToggleAction = new QAction(this);
    stakeMinerToggle(true);

    backupWalletAction = new QAction(QIcon(":/icons/filesave"), tr("&Backup Vault"), this);
    backupWalletAction->setToolTip(tr("Backup vault to another location"));
    dumpWalletAction = new QAction(QIcon(":/icons/tx_output"), tr("&Export Vault..."), this);
    dumpWalletAction->setToolTip(tr("Export vault's keys to a text file"));
    importWalletAction = new QAction(QIcon(":/icons/tx_input"), tr("&Import Vault..."), this);
    importWalletAction->setToolTip(tr("Import a file's keys into the vault"));
    changePassphraseAction = new QAction(QIcon(":/icons/key"), tr("&Change Passphrase"), this);
    changePassphraseAction->setToolTip(tr("Change the passphrase used for vault encryption"));
    openRPCConsoleAction = new QAction(tr("&Debug window"), this);
    openRPCConsoleAction->setToolTip(tr("Open debugging and diagnostic console"));
    verifyMessageAction = new QAction(QIcon(":/icons/transaction_0"), tr("&Verify message..."), this);
    verifyMessageAction->setToolTip(tr("Verify a message signature"));
	blockAction = new QAction(QIcon(":/icons/blexp"), tr("&Block Browser"), this);
    blockAction->setToolTip(tr("Explore the BlockChain"));

    connect(quitAction, SIGNAL(triggered()), qApp, SLOT(quit()));
    connect(optionsAction, SIGNAL(triggered()), this, SLOT(optionsClicked()));
    connect(aboutAction, SIGNAL(triggered()), this, SLOT(aboutClicked()));
    connect(aboutQtAction, SIGNAL(triggered()), qApp, SLOT(aboutQt()));
    connect(toggleHideAction, SIGNAL(triggered()), this, SLOT(toggleHidden()));
    connect(encryptWalletAction, SIGNAL(triggered(bool)), this, SLOT(encryptWallet(bool)));
    connect(backupWalletAction, SIGNAL(triggered()), this, SLOT(backupWallet()));
    connect(dumpWalletAction, SIGNAL(triggered()), this, SLOT(dumpWallet()));
    connect(importWalletAction, SIGNAL(triggered()), this, SLOT(importWallet()));
    connect(changePassphraseAction, SIGNAL(triggered()), this, SLOT(changePassphrase()));
    connect(verifyMessageAction, SIGNAL(triggered()), this, SLOT(verifyMessage()));
    connect(unlockWalletforposAction, SIGNAL(triggered()), this, SLOT(unlockWalletForMint()));
    connect(unlockWalletAction, SIGNAL(triggered()), this, SLOT(unlockWallet()));
    connect(lockWalletAction, SIGNAL(triggered()), this, SLOT(lockWallet()));
    connect(stakeMinerToggleAction, SIGNAL(triggered()), this, SLOT(stakeMinerToggle()));
    connect(blockAction, SIGNAL(triggered()), this, SLOT(gotoBlockBrowser()));
}

void BitcoinGUI::createMenuBar()
{
#ifdef Q_OS_MAC
    // Create a decoupled menu bar on Mac which stays even if the window is closed
    appMenuBar = new QMenuBar();
#else
    // Get the main window's menu bar on other platforms
    appMenuBar = menuBar();
#endif

    // Configure the menus
    QMenu *file = appMenuBar->addMenu(tr("&Vault"));
    file->addAction(backupWalletAction);
    file->addSeparator();
    file->addAction(dumpWalletAction);
    file->addAction(importWalletAction);
    file->addSeparator();
    file->addAction(exportAction);
#ifndef FIRST_CLASS_MESSAGING
    file->addAction(messageAction);
#endif
    file->addAction(verifyMessageAction);
    file->addSeparator();
    file->addAction(quitAction);
    file->setObjectName("fileMenu");

    QMenu *settings = appMenuBar->addMenu(tr("&Controls"));
    settings->addAction(encryptWalletAction);
    settings->addAction(changePassphraseAction);
    settings->addSeparator();
    settings->addAction(unlockWalletforposAction);
    settings->addAction(unlockWalletAction);
    settings->addAction(lockWalletAction);
	settings->addSeparator();
	settings->addAction(stakeMinerToggleAction);
    settings->addSeparator();
    settings->addAction(optionsAction);
    settings->setObjectName("settingsMenu");

    QMenu *help = appMenuBar->addMenu(tr("&Help"));
    help->addAction(openRPCConsoleAction);
    help->addSeparator();
    help->addAction(aboutAction);
    help->addAction(aboutQtAction);
    help->setObjectName("aboutMenu");

}

void BitcoinGUI::createToolBars()
{
    QToolBar *toolbar = addToolBar(tr("Tabs toolbar"));
    toolbar->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);
    toolbar->addAction(overviewAction);
    toolbar->addAction(sendCoinsAction);
    toolbar->addAction(receiveCoinsAction);
    toolbar->addAction(historyAction);
    toolbar->addAction(addressBookAction);
#ifdef FIRST_CLASS_MESSAGING
    toolbar->addAction(messageAction);
#endif

    QToolBar *toolbar2 = addToolBar(tr("Actions toolbar"));
    toolbar2->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);
    toolbar2->addAction(blockAction);
    toolbar2->addAction(exportAction);

}

void BitcoinGUI::setClientModel(ClientModel *clientModel)
{
    this->clientModel = clientModel;
    if(clientModel)
    {
        if(clientModel->isTestNet())
        {
            QString title_testnet = windowTitle() + QString(" ") + tr("[testnet]");
            setWindowTitle(title_testnet);
#ifndef Q_OS_MAC
            setWindowIcon(QIcon(":icons/version_testnet"));
#else
            MacDockIconHandler::instance()->setIcon(QIcon(":icons/version_testnet"));
#endif
            if(trayIcon)
            {
                trayIcon->setToolTip(title_testnet);
                trayIcon->setIcon(QIcon(":/icons/toolbar_testnet"));
            }
        }

        // Keep up to date with client
        setNumConnections(clientModel->getNumConnections());
        connect(clientModel, SIGNAL(numConnectionsChanged(int)), this, SLOT(setNumConnections(int)));

        setNumBlocks(clientModel->getNumBlocks(), clientModel->getNumBlocksOfPeers());
        connect(clientModel, SIGNAL(numBlocksChanged(int,int)), this, SLOT(setNumBlocks(int,int)));

        // Report errors from network/worker thread
        connect(clientModel, SIGNAL(message(QString,QString,unsigned int)), this, SLOT(message(QString,QString,unsigned int)));

        rpcConsole->setClientModel(clientModel);
    }
}

void BitcoinGUI::setWalletModel(WalletModel *walletModel)
{
    this->walletModel = walletModel;
    if(walletModel)
    {
        // Report errors from wallet thread
        connect(walletModel, SIGNAL(message(QString,QString,unsigned int)), this, SLOT(message(QString,QString,unsigned int)));

        // Put transaction list in tabs
        transactionView->setModel(walletModel);

        overviewPage->setModel(walletModel);
        addressBookPage->setModel(walletModel->getAddressTableModel());
        receiveCoinsPage->setModel(walletModel->getAddressTableModel());
        sendCoinsPage->setModel(walletModel);
        messagePage->setModel(walletModel);

        setEncryptionStatus(walletModel->getEncryptionStatus());
        connect(walletModel, SIGNAL(encryptionStatusChanged(int)), this, SLOT(setEncryptionStatus(int)));

        // Balloon popup for new transaction
        connect(walletModel->getTransactionTableModel(), SIGNAL(rowsInserted(QModelIndex,int,int)),
                this, SLOT(incomingTransaction(QModelIndex,int,int)));

        // Ask for passphrase if needed
        connect(walletModel, SIGNAL(requireUnlock()), this, SLOT(unlockWallet()));
    }
}

void BitcoinGUI::createTrayIcon()
{
    QMenu *trayIconMenu;
#ifndef Q_OS_MAC
    trayIcon = new QSystemTrayIcon(this);
    trayIconMenu = new QMenu(this);
    trayIcon->setContextMenu(trayIconMenu);
    trayIcon->setToolTip(tr("Version client"));
    trayIcon->setIcon(QIcon(":/icons/toolbar"));
    connect(trayIcon, SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
            this, SLOT(trayIconActivated(QSystemTrayIcon::ActivationReason)));
    trayIcon->show();
#else
    // Note: On Mac, the dock icon is used to provide the tray's functionality.
    MacDockIconHandler *dockIconHandler = MacDockIconHandler::instance();
    trayIconMenu = dockIconHandler->dockMenu();
#endif

    // Configuration of the tray icon (or dock icon) icon menu
    trayIconMenu->addAction(toggleHideAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(messageAction);
    trayIconMenu->addAction(verifyMessageAction);
#ifndef FIRST_CLASS_MESSAGING
    trayIconMenu->addSeparator();
#endif
    trayIconMenu->addAction(receiveCoinsAction);
    trayIconMenu->addAction(sendCoinsAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(optionsAction);
#ifndef Q_OS_MAC // This is built-in on Mac
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(quitAction);
#endif

    notificator = new Notificator(tr("version-qt"), trayIcon);
}

#ifndef Q_OS_MAC
void BitcoinGUI::trayIconActivated(QSystemTrayIcon::ActivationReason reason)
{
    if(reason == QSystemTrayIcon::Trigger)
    {
        // Click on system tray icon triggers "show/hide bitcoin"
        toggleHideAction->trigger();
    }
}
#endif

void BitcoinGUI::toggleHidden()
{
    // activateWindow() (sometimes) helps with keyboard focus on Windows
    if (isHidden())
    {
        show();
        activateWindow();
    }
    else if (isMinimized())
    {
        showNormal();
        activateWindow();
    }
    else if (GUIUtil::isObscured(this))
    {
        raise();
        activateWindow();
    }
    else
        hide();
}

void BitcoinGUI::optionsClicked()
{
    if(!clientModel || !clientModel->getOptionsModel())
        return;
    OptionsDialog dlg;
    dlg.setModel(clientModel->getOptionsModel());
    dlg.exec();
}

void BitcoinGUI::aboutClicked()
{
    AboutDialog dlg;
    dlg.setModel(clientModel);
    dlg.exec();
}

void BitcoinGUI::setNumConnections(int count)
{
    QString icon;
    switch(count)
    {
    case 0: icon = ":/icons/connect_0"; break;
    case 1: case 2: case 3: icon = ":/icons/connect_1"; break;
    case 4: case 5: case 6: icon = ":/icons/connect_2"; break;
    case 7: case 8: case 9: icon = ":/icons/connect_3"; break;
    default: icon = ":/icons/connect_4"; break;
    }
    labelConnectionsIcon->setPixmap(QIcon(icon).pixmap(STATUSBAR_ICONSIZE,STATUSBAR_ICONSIZE));
    labelConnectionsIcon->setToolTip(tr("%n active connection(s) to Version network", "", count));
}

void BitcoinGUI::setNumBlocks(int count, int nTotalBlocks)
{
    // don't show / hide progressBar and it's label if we have no connection(s) to the network
    if (!clientModel || clientModel->getNumConnections() == 0)
    {
        progressBarLabel->setVisible(false);
        progressBar->setVisible(false);

        return;
    }

    QString tooltip;

    if(count < nTotalBlocks)
    {
        int nRemainingBlocks = nTotalBlocks - count;
        float nPercentageDone = count / (nTotalBlocks * 0.01f);

        if (clientModel->getStatusBarWarnings() == "")
        {
            progressBarLabel->setText(tr("Synchronizing with network..."));
            progressBarLabel->setVisible(true);
            progressBar->setFormat(tr("~%n block(s) remaining", "", nRemainingBlocks));
            progressBar->setMaximum(nTotalBlocks);
            progressBar->setValue(count);
            progressBar->setVisible(true);
        }
        else
        {
            progressBarLabel->setText(clientModel->getStatusBarWarnings());
            progressBarLabel->setVisible(true);
            progressBar->setVisible(false);
        }
        tooltip = tr("Downloaded %1 of %2 blocks of transaction history (%3% done).").arg(count).arg(nTotalBlocks).arg(nPercentageDone, 0, 'f', 2);
    }
    else
    {
        if (clientModel->getStatusBarWarnings() == "")
            progressBarLabel->setVisible(false);
        else
        {
            progressBarLabel->setText(clientModel->getStatusBarWarnings());
            progressBarLabel->setVisible(true);
        }
        progressBar->setVisible(false);
        tooltip = tr("Downloaded %1 blocks of transaction history.").arg(count);
    }

    QDateTime now = QDateTime::currentDateTime();
    QDateTime lastBlockDate = clientModel->getLastBlockDate();
    int secs = lastBlockDate.secsTo(now);
    QString text;

    // Represent time from last generated block in human readable text
    if(secs <= 0)
    {
        // Fully up to date. Leave text empty.
    }
    else if(secs < 60)
    {
        text = tr("%n second(s) ago","",secs);
    }
    else if(secs < 60*60)
    {
        text = tr("%n minute(s) ago","",secs/60);
    }
    else if(secs < 24*60*60)
    {
        text = tr("%n hour(s) ago","",secs/(60*60));
    }
    else
    {
        text = tr("%n day(s) ago","",secs/(60*60*24));
    }

    // Set icon state: spinning if catching up, tick otherwise
    if(secs < 90*60 && count >= nTotalBlocks)
    {
        tooltip = tr("Up to date") + QString(".\n") + tooltip;
        labelBlocksIcon->setPixmap(QIcon(":/icons/synced").pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
    }
    else
    {
        tooltip = tr("Catching up...") + QString("\n") + tooltip;
        labelBlocksIcon->setMovie(syncIconMovie);
        syncIconMovie->start();
    }

    if(!text.isEmpty())
    {
        tooltip += QString("\n");
        tooltip += tr("Last received block was generated %1.").arg(text);
    }

    labelBlocksIcon->setToolTip(tooltip);
    progressBarLabel->setToolTip(tooltip);
    progressBar->setToolTip(tooltip);
}

void BitcoinGUI::message(const QString &title, const QString &message, unsigned int style)
{
  QString strTitle = tr("Version") + " - ";
  // Default to information icon
  int nMBoxIcon = QMessageBox::Information;
  int nNotifyIcon = Notificator::Information;

  // Check for usage of predefined title
  switch (style) {
  case CClientUIInterface::MSG_ERROR:
      strTitle += tr("Error");
      break;
  case CClientUIInterface::MSG_WARNING:
      strTitle += tr("Warning");
      break;
  case CClientUIInterface::MSG_INFORMATION:
      strTitle += tr("Information");
      break;
  default:
      strTitle += title; // Use supplied title
  }

  // Check for error/warning icon
  if (style & CClientUIInterface::ICON_ERROR) {
      nMBoxIcon = QMessageBox::Critical;
      nNotifyIcon = Notificator::Critical;
  }
  else if (style & CClientUIInterface::ICON_WARNING) {
      nMBoxIcon = QMessageBox::Warning;
      nNotifyIcon = Notificator::Warning;
  }

  // Display message
  if (style & CClientUIInterface::MODAL) {
      // Check for buttons, use OK as default, if none was supplied
      QMessageBox::StandardButton buttons;
      if (!(buttons = (QMessageBox::StandardButton)(style & CClientUIInterface::BTN_MASK)))
          buttons = QMessageBox::Ok;

      QMessageBox mBox((QMessageBox::Icon)nMBoxIcon, strTitle, message, buttons);
      mBox.exec();
  }
  else
      notificator->notify((Notificator::Class)nNotifyIcon, strTitle, message);
}

void BitcoinGUI::changeEvent(QEvent *e)
{
    QMainWindow::changeEvent(e);
#ifndef Q_OS_MAC // Ignored on Mac
    if(e->type() == QEvent::WindowStateChange)
    {
        if(clientModel && clientModel->getOptionsModel()->getMinimizeToTray())
        {
            QWindowStateChangeEvent *wsevt = static_cast<QWindowStateChangeEvent*>(e);
            if(!(wsevt->oldState() & Qt::WindowMinimized) && isMinimized())
            {
                QTimer::singleShot(0, this, SLOT(hide()));
                e->ignore();
            }
        }
    }
#endif
}

void BitcoinGUI::closeEvent(QCloseEvent *event)
{
    if(clientModel)
    {
#ifndef Q_OS_MAC // Ignored on Mac
        if(!clientModel->getOptionsModel()->getMinimizeToTray() &&
           !clientModel->getOptionsModel()->getMinimizeOnClose())
        {
            qApp->quit();
        }
#endif
    }
    QMainWindow::closeEvent(event);
}

void BitcoinGUI::askFee(qint64 nFeeRequired, bool *payFee)
{
    QString strMessage =
        tr("This transaction is over the size limit.  You can still send it for a fee of %1, "
          "which goes to the nodes that process your transaction and helps to support the network.  "
          "Do you want to pay the fee?").arg(
                BitcoinUnits::formatWithUnit(BitcoinUnits::BTC, nFeeRequired));
    QMessageBox::StandardButton retval = QMessageBox::question(
          this, tr("Sending..."), strMessage,
          QMessageBox::Yes|QMessageBox::Cancel, QMessageBox::Yes);
    *payFee = (retval == QMessageBox::Yes);
}

void BitcoinGUI::incomingTransaction(const QModelIndex & parent, int start, int end)
{
    if(!walletModel || !clientModel)
        return;
    TransactionTableModel *ttm = walletModel->getTransactionTableModel();
    qint64 amount = ttm->index(start, TransactionTableModel::Amount, parent)
                    .data(Qt::EditRole).toULongLong();
    if(!clientModel->inInitialBlockDownload())
    {
        // On new transaction, make an info balloon
        // Unless the initial block download is in progress, to prevent balloon-spam
        QString date = ttm->index(start, TransactionTableModel::Date, parent)
                        .data().toString();
        QString type = ttm->index(start, TransactionTableModel::Type, parent)
                        .data().toString();
        QString address = ttm->index(start, TransactionTableModel::ToAddress, parent)
                        .data().toString();
        QIcon icon = qvariant_cast<QIcon>(ttm->index(start,
                            TransactionTableModel::ToAddress, parent)
                        .data(Qt::DecorationRole));

        message((amount)<0 ? tr("Sent transaction") : tr("Incoming transaction"),
           tr("Date: %1\n"
              "Amount: %2\n"
              "Type: %3\n"
              "Address: %4\n")
                .arg(date)
                .arg(BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), amount, true))
                .arg(type)
                .arg(address), CClientUIInterface::MSG_INFORMATION);

    }
}

void BitcoinGUI::gotoOverviewPage()
{
    overviewAction->setChecked(true);
    centralWidget->setCurrentWidget(overviewPage);

    exportAction->setEnabled(false);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
}

void BitcoinGUI::gotoHistoryPage()
{
    historyAction->setChecked(true);
    centralWidget->setCurrentWidget(transactionsPage);

    exportAction->setEnabled(true);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
    connect(exportAction, SIGNAL(triggered()), transactionView, SLOT(exportClicked()));
}

void BitcoinGUI::gotoAddressBookPage()
{
    addressBookAction->setChecked(true);
    centralWidget->setCurrentWidget(addressBookPage);

    exportAction->setEnabled(true);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
    connect(exportAction, SIGNAL(triggered()), addressBookPage, SLOT(exportClicked()));
}

void BitcoinGUI::gotoBlockBrowser(QString transactionId)
{
    if(!transactionId.isEmpty())
    blockBrowser->setTransactionId(transactionId);
    
    blockBrowser->show();
}

void BitcoinGUI::gotoReceiveCoinsPage()
{
    receiveCoinsAction->setChecked(true);
    centralWidget->setCurrentWidget(receiveCoinsPage);

    exportAction->setEnabled(true);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
    connect(exportAction, SIGNAL(triggered()), receiveCoinsPage, SLOT(exportClicked()));
}

void BitcoinGUI::gotoSendCoinsPage()
{
    sendCoinsAction->setChecked(true);
    centralWidget->setCurrentWidget(sendCoinsPage);

    exportAction->setEnabled(false);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
}

void BitcoinGUI::gotoMessagePage()
{
#ifdef FIRST_CLASS_MESSAGING
    messageAction->setChecked(true);
    centralWidget->setCurrentWidget(messagePage);

    exportAction->setEnabled(false);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
#else
    messagePage->show();
    messagePage->setFocus();
#endif
}

void BitcoinGUI::gotoMessagePage(QString addr)
{
    gotoMessagePage();
    messagePage->setAddress(addr);
}

void BitcoinGUI::dragEnterEvent(QDragEnterEvent *event)
{
    // Accept only URIs
    if(event->mimeData()->hasUrls())
        event->acceptProposedAction();
}

void BitcoinGUI::dropEvent(QDropEvent *event)
{
    if(event->mimeData()->hasUrls())
    {
        gotoSendCoinsPage();
        QList<QUrl> uris = event->mimeData()->urls();
        foreach(const QUrl &uri, uris)
        {
            sendCoinsPage->handleURI(uri.toString());
        }
    }

    event->acceptProposedAction();
}

void BitcoinGUI::handleURI(QString strURI)
{
    gotoSendCoinsPage();
    sendCoinsPage->handleURI(strURI);

    if(!isActiveWindow())
        activateWindow();

    showNormalIfMinimized();
}

void BitcoinGUI::setEncryptionStatus(int status)
{
    switch(status)
    {
    case WalletModel::Unencrypted:
        labelEncryptionIcon->hide();
        encryptWalletAction->setChecked(false);
        unlockWalletforposAction->setChecked(false);
        unlockWalletAction->setChecked(false);
        lockWalletAction->setChecked(false);
        changePassphraseAction->setEnabled(false);
        unlockWalletforposAction->setEnabled(false);
        unlockWalletAction->setEnabled(false);
        lockWalletAction->setEnabled(false);
        encryptWalletAction->setEnabled(true);
        break;
    case WalletModel::Unlocked:
        labelEncryptionIcon->show();
        labelEncryptionIcon->setPixmap(QIcon(":/icons/lock_open").pixmap(STATUSBAR_ICONSIZE,STATUSBAR_ICONSIZE));
        labelEncryptionIcon->setToolTip(pwalletMain->fWalletUnlockMintOnly? tr("Vault is <b>encrypted</b> and currently <b>unlocked for block minting only</b>") : tr("Vault is <b>encrypted</b> and currently <b>unlocked</b>"));
        encryptWalletAction->setChecked(true);
        unlockWalletforposAction->setChecked(true);
        unlockWalletAction->setChecked(true);
        lockWalletAction->setChecked(true);
        changePassphraseAction->setEnabled(true);
        encryptWalletAction->setEnabled(false); // TODO: decrypt currently not supported
        unlockWalletforposAction->setEnabled(false);
        unlockWalletAction->setEnabled(false);
        lockWalletAction->setEnabled(true);
        break;
    case WalletModel::Locked:
        labelEncryptionIcon->show();
        labelEncryptionIcon->setPixmap(QIcon(":/icons/lock_closed").pixmap(STATUSBAR_ICONSIZE,STATUSBAR_ICONSIZE));
        labelEncryptionIcon->setToolTip(tr("Wallet is <b>encrypted</b> and currently <b>locked</b>"));
        encryptWalletAction->setChecked(true);
        unlockWalletforposAction->setChecked(true);
        unlockWalletAction->setChecked(true);
        lockWalletAction->setChecked(true);
        changePassphraseAction->setEnabled(true);
        encryptWalletAction->setEnabled(false); // TODO: decrypt currently not supported
        unlockWalletforposAction->setEnabled(true);
        unlockWalletAction->setEnabled(true);
        lockWalletAction->setEnabled(false);
        break;
    }
}

void BitcoinGUI::encryptWallet(bool status)
{
    if(!walletModel)
        return;
    AskPassphraseDialog dlg(status ? AskPassphraseDialog::Encrypt:
                                     AskPassphraseDialog::Decrypt, this);
    dlg.setModel(walletModel);
    dlg.exec();

    setEncryptionStatus(walletModel->getEncryptionStatus());
}

void BitcoinGUI::backupWallet()
{
#if QT_VERSION < 0x050000
    QString saveDir = QDesktopServices::storageLocation(QDesktopServices::DocumentsLocation);
#else
    QString saveDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
#endif
    QString filename = QFileDialog::getSaveFileName(this, tr("Backup Vault"), saveDir, tr("Vault Data (*.dat)"));
    if(!filename.isEmpty()) {
        if(!walletModel->backupWallet(filename)) {
            QMessageBox::warning(this, tr("Backup Failed"), tr("There was an error trying to save the vault data to the new location."));
        }
    }
}

void BitcoinGUI::dumpWallet()
{
   if(!walletModel)
      return;

   WalletModel::UnlockContext ctx(walletModel->requestUnlock());
   if(!ctx.isValid())
   {
       // Unlock wallet failed or was cancelled
       return;
   }

#if QT_VERSION < 0x050000
    QString saveDir = QDesktopServices::storageLocation(QDesktopServices::DocumentsLocation);
#else
    QString saveDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
#endif
    QString filename = QFileDialog::getSaveFileName(this, tr("Export Wallet"), saveDir, tr("Wallet Text (*.txt)"));
    if(!filename.isEmpty()) {
        if(!walletModel->dumpWallet(filename)) {
            message(tr("Export Failed"),
                         tr("There was an error trying to save the wallet's keys to your location.\n"
                            "Keys were not saved")
                      ,CClientUIInterface::MSG_ERROR);
        }
        else
            message(tr("Export Successful"),
                       tr("Keys were saved to:\n %1")
                       .arg(filename)
                      ,CClientUIInterface::MSG_INFORMATION);
    }
}

void BitcoinGUI::importWallet()
{
   if(!walletModel)
      return;

   WalletModel::UnlockContext ctx(walletModel->requestUnlock());
   if(!ctx.isValid())
   {
       // Unlock wallet failed or was cancelled
       return;
   }

#if QT_VERSION < 0x050000
    QString openDir = QDesktopServices::storageLocation(QDesktopServices::DocumentsLocation);
#else
    QString openDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
#endif
    QString filename = QFileDialog::getOpenFileName(this, tr("Import Wallet"), openDir, tr("Wallet Text (*.txt)"));
    if(!filename.isEmpty()) {
        if(!walletModel->importWallet(filename)) {
            message(tr("Import Failed"),
                         tr("There was an error trying to import the file's keys into your wallet.\n"
                            "Some or all keys were not imported from walletfile: %1")
                         .arg(filename)
                      ,CClientUIInterface::MSG_ERROR);
        }
        else
            message(tr("Import Successful"),
                       tr("Keys %1, were imported into wallet.")
                       .arg(filename)
                      ,CClientUIInterface::MSG_INFORMATION);
    }
}

void BitcoinGUI::changePassphrase()
{
    AskPassphraseDialog dlg(AskPassphraseDialog::ChangePass, this);
    dlg.setModel(walletModel);
    dlg.exec();
}

void BitcoinGUI::verifyMessage()
{
    VerifyMessageDialog *dlg = new VerifyMessageDialog(this);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->show();
}

void BitcoinGUI::unlockWallet()
{
    if(!walletModel)
        return;
    // Unlock wallet when requested by wallet model
    if(walletModel->getEncryptionStatus() == WalletModel::Locked)
    {
        AskPassphraseDialog dlg(AskPassphraseDialog::Unlock, this);
        dlg.setModel(walletModel);
        dlg.exec();

        // Only show message if unlock is sucessfull.
        if(walletModel->getEncryptionStatus() == WalletModel::Unlocked)
          message(tr("Unlock Wallet Information"),
                  tr("Wallet has been unlocked. \n"
                     "Proof of Stake has started.\n")
                  ,CClientUIInterface::MSG_INFORMATION);
    }
}

void BitcoinGUI::unlockWalletForMint()
{
    if(!walletModel)
        return;

    // Unlock wallet when requested by user
    if(walletModel->getEncryptionStatus() == WalletModel::Locked)
    {
        AskPassphraseDialog dlg(AskPassphraseDialog::UnlockForMint, this);
        dlg.setModel(walletModel);
        dlg.exec();

        // Only show message if unlock is sucessfull.
        if(walletModel->getEncryptionStatus() == WalletModel::Unlocked)
          message(tr("Unlock Wallet Information"),
                  tr("Wallet has been unlocked for staking only. \n"
                     "Proof of Stake has started.\n")
                  ,CClientUIInterface::MSG_INFORMATION);
    }
}

void BitcoinGUI::lockWallet()
{
    if(!walletModel)
       return;

    // Lock wallet when requested by user
    if(walletModel->getEncryptionStatus() == WalletModel::Unlocked)
         walletModel->setWalletLocked(true,"",true);

        // Only show message if lock is sucessfull.
        if(walletModel->getEncryptionStatus() == WalletModel::Locked)
    message(tr("Lock Wallet Information"),
            tr("Wallet has been locked.\n"
                  "Proof of Stake has stopped.\n")
            ,CClientUIInterface::MSG_INFORMATION);

}

// Enables or disables the internal stake miner;
// only sets the menu icon and text on the initial run 
void BitcoinGUI::stakeMinerToggle(bool fInitial) {
    bool fStakingInt = fStaking;

    if(fInitial) {
        fStakingInt = GetBoolArg("-staking", fStaking);
        fStakingInt = ~fStakingInt & 0x1;
    }

    if(fStakingInt) {
        if(!fInitial) fStaking = false;
        stakeMinerToggleAction->setIcon(QIcon(":/icons/staking_on"));
        stakeMinerToggleAction->setText(tr("&Enable PoS mining"));
    } else {
        if(!fInitial) fStaking = true;
        stakeMinerToggleAction->setIcon(QIcon(":/icons/staking_off"));
        stakeMinerToggleAction->setText(tr("&Disable PoS mining"));
    }

    if(!fInitial)
      updateStakingIcon();
}

void BitcoinGUI::showNormalIfMinimized()
{
    if(!isVisible()) // Show, if hidden
        show();
    if(isMinimized()) // Unminimize, if minimized
        showNormal();
}

void BitcoinGUI::updateStakingIcon()
{
    uint64_t nMinWeight = 0, nMaxWeight = 0, nWeight = 0;
    if (pwalletMain)
        pwalletMain->GetStakeWeight(*pwalletMain, nMinWeight, nMaxWeight, nWeight);

     if (!fStaking)
    {
	labelStakingIcon->setPixmap(QIcon(":/icons/staking_off").pixmap(STATUSBAR_ICONSIZE,STATUSBAR_ICONSIZE));
        labelStakingIcon->setToolTip(tr("Not staking because staking is disabled."));
    }
else if (nLastCoinStakeSearchInterval && nWeight)
    {
        uint64_t nNetworkWeight = GetPoSKernelPS();
        unsigned nEstimateTime = nStakeTargetSpacing * nNetworkWeight / nWeight;

        QString text;
        if (nEstimateTime < 60)
        {
            text = tr("%n second(s)", "", nEstimateTime);
        }
        else if (nEstimateTime < 60*60)
        {
            text = tr("%n minute(s)", "", nEstimateTime/60);
        }
        else if (nEstimateTime < 24*60*60)
        {
            text = tr("%n hour(s)", "", nEstimateTime/(60*60));
        }
        else
        {
            text = tr("%n day(s)", "", nEstimateTime/(60*60*24));
        }

        labelStakingIcon->setPixmap(QIcon(":/icons/staking_on").pixmap(STATUSBAR_ICONSIZE,STATUSBAR_ICONSIZE));
        labelStakingIcon->setToolTip(tr("Staking.<br>Your weight is %1<br>Network weight is %2<br>Expected time to earn reward is %3").arg(nWeight).arg(nNetworkWeight).arg(text));
    }
    else
    {
        labelStakingIcon->setPixmap(QIcon(":/icons/staking_off").pixmap(STATUSBAR_ICONSIZE,STATUSBAR_ICONSIZE));
        if (pwalletMain && pwalletMain->IsLocked())
            labelStakingIcon->setToolTip(tr("Not staking because vault is locked"));
        else if (vNodes.empty())
            labelStakingIcon->setToolTip(tr("Not staking because vault is offline"));
        else if (clientModel->getNumConnections() < 2 )
            labelStakingIcon->setToolTip(tr("Not staking because vault is still acquiring nodes"));
        else if (IsInitialBlockDownload() || clientModel->getNumBlocks() < clientModel->getNumBlocksOfPeers())
            labelStakingIcon->setToolTip(tr("Not staking because vault is syncing"));
        else if (!nWeight)
            labelStakingIcon->setToolTip(tr("Not staking because you don't have mature coins"));
        else
            labelStakingIcon->setToolTip(tr("Not staking"));
    }
}

void BitcoinGUI::updateStyleSlot()
{
    updateStyle();
}

void BitcoinGUI::updateStyle()
{
    if (!fUseVTheme)
        return;

    QString qssPath = QString::fromStdString( GetDataDir().string() ) + "/version.qss";

    QFile f( qssPath );

    if (!f.exists())
        writeDefaultStyleSheet( qssPath );

    if (!f.open(QFile::ReadOnly))
    {
        qDebug() << "failed to open style sheet";
        return;
    }

    qDebug() << "loading theme";
    qApp->setStyleSheet( f.readAll() );
}

void BitcoinGUI::writeDefaultStyleSheet(const QString &qssPath)
{
    qDebug() << "writing default style sheet";

    QFile qss( ":/text/stylesheet" );
    qss.open( QFile::ReadOnly );

    QFile f( qssPath );
    f.open( QFile::ReadWrite );
    f.write( qss.readAll() );
}
