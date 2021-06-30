HSE=`which hse`
INJECT=`which cndb_txn_inject`
KVSDROP=`which cndb_simpledrop_inject`
KVSDROP_RECOVERY=`which cndb_simpledrop_recovery_inject`
CNDB_LOG=`which cndb_log`
MDC_TOOL=`which mdc_tool`
KVDBDIR?=kvdbs
IMGTARGETS=empty.klog missing_ackds.cndblog missing_ackc.cndblog wrongingestid.cndblog simpledrop.cndblog simpledrop_recovery.cndblog
CTARGETS=simpledrop.c simpledrop_recovery.c

all: clean $(IMGTARGETS) $(CTARGETS)

clean:
	rm -f $(IMGTARGETS)
	rm -rf $(KVDBDIR)
	mkdir -p ${KVDBDIR}

empty.klog:
	mkdir $(KVDBDIR)/empty
	$(HSE) -C $(KVDBDIR)/empty kvdb create
	$(MDC_TOOL) -i -w $@ $(KVDBDIR)/empty

missing_ackds.cndblog:
	mkdir $(KVDBDIR)/rollforward
	$(HSE) -C $(KVDBDIR)/rollforward kvdb create
	$(INJECT) -f $(KVDBDIR)/rollforward
	$(CNDB_LOG) -w $@ $(KVDBDIR)/rollforward

missing_ackc.cndblog:
	mkdir $(KVDBDIR)/rollbackward
	$(HSE) -C $(KVDBDIR)/rollbackward kvdb create
	$(INJECT) -b $(KVDBDIR)/rollbackward
	$(CNDB_LOG) -w $@ $(KVDBDIR)/rollbackward

wrongingestid.cndblog:
	mkdir $(KVDBDIR)/wrongingestid
	$(HSE) -C $(KVDBDIR)/wrongingestid kvdb create
	$(INJECT) -i $(KVDBDIR)/wrongingestid
	$(CNDB_LOG) -w $@ $(KVDBDIR)/wrongingestid

simpledrop_recovery.cndblog:
	mkdir $(KVDBDIR)/simpledrop_recovery
	$(HSE) -C $(KVDBDIR)/simpledrop_recovery kvdb create
	$(KVSDROP_RECOVERY) $(KVDBDIR)/simpledrop_recovery
	$(CNDB_LOG) -w $@ $(KVDBDIR)/simpledrop_recovery

simpledrop.cndblog:
	mkdir $(KVDBDIR)/simpledrop
	$(HSE) -C $(KVDBDIR)/simpledrop kvdb create
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
