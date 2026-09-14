
#include "macdockiconhandler.h"

#include <QtGui/QImage>
#include <QtWidgets/QMenu>
#include <QtWidgets/QWidget>

extern void qt_mac_set_dock_menu(QMenu*);

#undef slots
#include <Cocoa/Cocoa.h>

@interface DockIconClickEventHandler : NSObject
{
    MacDockIconHandler* dockIconHandler;
}

@end

@implementation DockIconClickEventHandler

- (id)initWithDockIconHandler:(MacDockIconHandler *)aDockIconHandler
{
    self = [super init];
    if (self) {
        dockIconHandler = aDockIconHandler;

        [[NSAppleEventManager sharedAppleEventManager]
            setEventHandler:self
                andSelector:@selector(handleDockClickEvent:withReplyEvent:)
              forEventClass:kCoreEventClass
                 andEventID:kAEReopenApplication];
    }
    return self;
}

- (void)handleDockClickEvent:(NSAppleEventDescriptor*)event withReplyEvent:(NSAppleEventDescriptor*)replyEvent
{
    Q_UNUSED(event)
    Q_UNUSED(replyEvent)

    if (dockIconHandler)
        dockIconHandler->handleDockIconClickEvent();
}

@end

// QPixmap::toMacCGImageRef() and QtMacExtras' QtMac::toCGImageRef() are both
// gone (the former removed with Qt4, the latter deprecated then dropped by
// Qt 5.14+), so convert via raw ARGB32 image data instead. The QImage is
// heap-allocated and freed once CoreGraphics is done with its backing data.
static void ReleaseQImageData(void *info, const void *data, size_t size)
{
    Q_UNUSED(data);
    Q_UNUSED(size);
    delete static_cast<QImage *>(info);
}

static CGImageRef QImageToCGImage(const QImage &image)
{
    QImage *img = new QImage(image.convertToFormat(QImage::Format_ARGB32));
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGDataProviderRef provider = CGDataProviderCreateWithData(
        img, img->constBits(), img->sizeInBytes(), ReleaseQImageData);
    CGImageRef cgImage = CGImageCreate(
        img->width(), img->height(), 8, 32, img->bytesPerLine(), colorSpace,
        kCGBitmapByteOrder32Little | kCGImageAlphaPremultipliedFirst,
        provider, NULL, false, kCGRenderingIntentDefault);
    CGDataProviderRelease(provider);
    CGColorSpaceRelease(colorSpace);
    return cgImage;
}

MacDockIconHandler::MacDockIconHandler() : QObject()
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    this->m_dockIconClickEventHandler = (objc_object *)[[DockIconClickEventHandler alloc] initWithDockIconHandler:this];

    this->m_dummyWidget = new QWidget();
    this->m_dockMenu = new QMenu(this->m_dummyWidget);
    qt_mac_set_dock_menu(this->m_dockMenu);
    [pool release];
}

MacDockIconHandler::~MacDockIconHandler()
{
    [this->m_dockIconClickEventHandler release];
    delete this->m_dummyWidget;
}

QMenu *MacDockIconHandler::dockMenu()
{
    return this->m_dockMenu;
}

void MacDockIconHandler::setIcon(const QIcon &icon)
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    NSImage *image;
    if (icon.isNull())
        image = [[NSImage imageNamed:@"NSApplicationIcon"] retain];
    else {
        QSize size = icon.actualSize(QSize(128, 128));
        QPixmap pixmap = icon.pixmap(size);
        CGImageRef cgImage = QImageToCGImage(pixmap.toImage());
        image = [[NSImage alloc] initWithCGImage:cgImage size:NSZeroSize];
        CFRelease(cgImage);
    }

    [NSApp setApplicationIconImage:image];
    [image release];
    [pool release];
}

MacDockIconHandler *MacDockIconHandler::instance()
{
    static MacDockIconHandler *s_instance = NULL;
    if (!s_instance)
        s_instance = new MacDockIconHandler();
    return s_instance;
}

void MacDockIconHandler::handleDockIconClickEvent()
{
    emit this->dockIconClicked();
}
