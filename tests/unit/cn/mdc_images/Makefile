HSE := $(shell command -v hse)
INJECT := $(shell command -v cndb_txn_inject)
KVSDROP := $(shell command -v cndb_simpledrop_inject)
KVSDROP_RECOVERY := $(shell command -v cndb_simpledrop_recovery_inject)
CNDB_LOG := $(shell command -v cndb_log)
MDC_TOOL := $(shell command -v mdc_tool)
KVDBDIR ?= kvdbs
CTARGETS := simpledrop.c simpledrop_recovery.c

ifeq ($(shell hse -Vv | grep BIG_ENDIAN),)
SUFFIX := cndblog
else
SUFFIX := cndblog-be
endif

IMGTARGETS := \
	missing_ackds.${SUFFIX} \
	missing_ackc.${SUFFIX} \
	wrongingestid.${SUFFIX} \
	simpledrop.${SUFFIX} \
	simpledrop_recovery.${SUFFIX}

all: clean $(IMGTARGETS) $(CTARGETS)

clean:
	rm -f $(IMGTARGETS)
	rm -rf $(KVDBDIR)
	mkdir -p ${KVDBDIR}

missing_ackds.${SUFFIX}:
	mkdir $(KVDBDIR)/rollforward
	$(HSE) kvdb create $(KVDBDIR)/rollforward
	$(INJECT) -f $(KVDBDIR)/rollforward
	$(CNDB_LOG) -w $@ $(KVDBDIR)/rollforward

missing_ackc.${SUFFIX}:
	mkdir $(KVDBDIR)/rollbackward
	$(HSE) kvdb create $(KVDBDIR)/rollbackward
	$(INJECT) -b $(KVDBDIR)/rollbackward
	$(CNDB_LOG) -w $@ $(KVDBDIR)/rollbackward

wrongingestid.${SUFFIX}:
	mkdir $(KVDBDIR)/wrongingestid
	$(HSE) kvdb create $(KVDBDIR)/wrongingestid
	$(INJECT) -i $(KVDBDIR)/wrongingestid
	$(CNDB_LOG) -w $@ $(KVDBDIR)/wrongingestid

simpledrop_recovery.${SUFFIX}:
	mkdir $(KVDBDIR)/simpledrop_recovery
	$(HSE) kvdb create $(KVDBDIR)/simpledrop_recovery
	$(KVSDROP_RECOVERY) $(KVDBDIR)/simpledrop_recovery
	$(CNDB_LOG) -w $@ $(KVDBDIR)/simpledrop_recovery

simpledrop.${SUFFIX}:
	mkdir $(KVDBDIR)/simpledrop
	$(HSE) kvdb create $(KVDBDIR)/simpledrop
	$(KVSDROP) $(KVDBDIR)/simpledrop
	$(CNDB_LOG) -w $@ $(KVDBDIR)/simpledrop

simpledrop.c: simpledrop_cndblog.txt cndblog2c.awk
	awk -f cndblog2c.awk $< | sed 's:.*:& /* do not edit, see top of file for instructions */:'> ../../../../tools/cndb_tests/$@
	touch ../../../../tools/cndb_tests/cndb_simpledrop_inject.c

# simpledrop_recovery.cndblog.txt is created by copying simpledrop.cndblog.txt
# and manually adding an INFOD record for cnid 3
simpledrop_recovery.c: simpledrop_recovery_cndblog.txt cndblog2c.awk
	awk -f cndblog2c.awk $< | sed 's:.*:& /* do not edit, see top of file for instructions */:'> ../../../../tools/cndb_tests/$@
	touch ../../../../tools/cndb_tests/cndb_simpledrop_recovery_inject.c
