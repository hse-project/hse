HSE=`which hse`
INJECT=`which cndb_txn_inject`
KVSDROP=`which cndb_simpledrop_inject`
KVSDROP_RECOVERY=`which cndb_simpledrop_recovery_inject`
CNDB_LOG=`which cndb_log`
MDC_TOOL=`which mdc_tool`
SUDO?=sudo
MPIMAGES?=mp1
IMGTARGETS=empty.klog missing_ackds.cndblog missing_ackc.cndblog wrongingestid.cndblog simpledrop.cndblog simpledrop_recovery.cndblog
CTARGETS=simpledrop.c simpledrop_recovery.c

all: clean $(IMGTARGETS) $(CTARGETS)

clean:
	-$(SUDO) $(HSE) kvdb destroy $(MPIMAGES)/empty
	-$(SUDO) $(HSE) kvdb destroy $(MPIMAGES)/10_kvses
	-$(SUDO) $(HSE) kvdb destroy $(MPIMAGES)/rollforward
	-$(SUDO) $(HSE) kvdb destroy $(MPIMAGES)/rollbackward
	-$(SUDO) $(HSE) kvdb destroy $(MPIMAGES)/wrongingestid
	-$(SUDO) $(HSE) kvdb destroy $(MPIMAGES)/simpledrop
	-$(SUDO) $(HSE) kvdb destroy $(MPIMAGES)/simpledrop_recovery
	rm -f $(IMGTARGETS)

empty.klog:
	$(SUDO) $(HSE) kvdb create $(MPIMAGES)/empty
	$(SUDO) $(MDC_TOOL) -i -w $@ $(MPIMAGES) empty

# this is deprecated because kvses no longer live in kvdb_log
# [HSE_REVISIT] consider resurrecting this test in cndb_log_test
#10_kvses.klog:
#	$(SUDO) $(HSE) kvdb create $(MPIMAGES)/10_kvses
#	$(SUDO) $(HSE) kvs create $(MPIMAGES)/10_kvses/kvs0
#	$(SUDO) $(HSE) kvs create $(MPIMAGES)/10_kvses/kvs1
#	$(SUDO) $(HSE) kvs create $(MPIMAGES)/10_kvses/kvs2
#	$(SUDO) $(HSE) kvs create $(MPIMAGES)/10_kvses/kvs3
#	$(SUDO) $(HSE) kvs create $(MPIMAGES)/10_kvses/kvs4
#	$(SUDO) $(HSE) kvs create $(MPIMAGES)/10_kvses/kvs5
#	$(SUDO) $(HSE) kvs create $(MPIMAGES)/10_kvses/kvs6
#	$(SUDO) $(HSE) kvs create $(MPIMAGES)/10_kvses/kvs7
#	$(SUDO) $(HSE) kvs create $(MPIMAGES)/10_kvses/kvs8
#	$(SUDO) $(HSE) kvs create $(MPIMAGES)/10_kvses/kvs9
#	$(SUDO) $(MDC_TOOL) -i -w $@ $(MPIMAGES) 10_kvses

missing_ackds.cndblog:
	$(SUDO) $(HSE) kvdb create $(MPIMAGES)/rollforward
	$(SUDO) $(INJECT) -f $(MPIMAGES) rollforward
	$(SUDO) $(CNDB_LOG) -w $@ $(MPIMAGES) rollforward

missing_ackc.cndblog:
	$(SUDO) $(HSE) kvdb create $(MPIMAGES)/rollbackward
	$(SUDO) $(INJECT) -b $(MPIMAGES) rollbackward
	$(SUDO) $(CNDB_LOG) -w $@ $(MPIMAGES) rollbackward

wrongingestid.cndblog:
	$(SUDO) $(HSE) kvdb create $(MPIMAGES)/wrongingestid
	$(SUDO) $(INJECT) -i $(MPIMAGES) wrongingestid
	$(SUDO) $(CNDB_LOG) -w $@ $(MPIMAGES) wrongingestid

simpledrop_recovery.cndblog:
	$(SUDO) $(HSE) kvdb create $(MPIMAGES)/simpledrop_recovery
	$(SUDO) $(KVSDROP_RECOVERY) $(MPIMAGES) simpledrop_recovery
	$(SUDO) $(CNDB_LOG) -w $@ $(MPIMAGES) simpledrop_recovery

simpledrop.cndblog:
	$(SUDO) $(HSE) kvdb create $(MPIMAGES)/simpledrop
	$(SUDO) $(KVSDROP) $(MPIMAGES) simpledrop
	$(SUDO) $(CNDB_LOG) -w $@ $(MPIMAGES) simpledrop

simpledrop.c: simpledrop_cndblog.txt cndblog2c.awk
	awk -f cndblog2c.awk $< | sed 's:.*:& /* do not edit, see top of file for instructions */:'> $@
	touch ../cndb_simpledrop_inject.c

# simpledrop_recovery.cndblog.txt is created by copying simpledrop.cndblog.txt 
# and manually adding an INFOD record for cnid 3
simpledrop_recovery.c: simpledrop_recovery_cndblog.txt cndblog2c.awk
	awk -f cndblog2c.awk $< | sed 's:.*:& /* do not edit, see top of file for instructions */:'> $@
	touch ../cndb_simpledrop_recovery_inject.c
