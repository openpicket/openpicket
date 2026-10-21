import { Anchor, Breadcrumbs } from "@mantine/core";
import { Link, useNavigate, useParams } from "react-router";
import { AlertDetail } from "../components/AlertDetail";
import { PageHeader } from "../components/common";
import { t } from "../lib/i18n";

export default function AlertPage() {
  const { instance = "", id = "0" } = useParams();
  const navigate = useNavigate();
  return (
    <>
      <Breadcrumbs mb="xs">
        <Anchor component={Link} to="/alerts" size="sm">
          {t("Alerts")}
        </Anchor>
        <span>#{id}</span>
      </Breadcrumbs>
      <PageHeader title={t("Alert #{id}", { id })} description={instance} />
      <AlertDetail instance={instance} id={BigInt(/^\d+$/.test(id) ? id : "0")} onDeleted={() => navigate("/alerts")} />
    </>
  );
}
