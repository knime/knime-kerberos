---Add the context.workflow.user, user who executes workflow to the postgers DB. 
---CREATE ROLE "POSTGRES/pg.ad.testing.knime@AD.TESTING.KNIME" SUPERUSER LOGIN;
CREATE ROLE "knimeserver/client.ad.testing.knime" SUPERUSER LOGIN;
CREATE ROLE "jenkins" SUPERUSER LOGIN;