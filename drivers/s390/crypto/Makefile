#
# S/390 crypto devices
#

ap-objs := ap_bus.o
obj-$(subst m,y,$(CONFIG_ZCRYPT)) += ap.o
# zcrypt_api depends on ap
obj-$(subst m,y,$(CONFIG_ZCRYPT)) += zcrypt_api.o
# msgtype* depend on zcrypt_api
obj-$(subst m,y,$(CONFIG_ZCRYPT)) += zcrypt_msgtype6.o zcrypt_msgtype50.o
# adapter drivers depend on ap, zcrypt_api and msgtype*
obj-$(CONFIG_ZCRYPT) += zcrypt_pcixcc.o zcrypt_cex2a.o zcrypt_cex4.o
