import { useRoute, href } from './router';
import { Header, MockBanner } from './components/Header';
import { TokenDialog } from './components/TokenDialog';
import { InvestigatePage } from './pages/InvestigatePage';
import { ReportPage } from './pages/ReportPage';
import { HistoryPage } from './pages/HistoryPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { Empty } from './components/Section';

export function App() {
  const route = useRoute();
  let page;
  switch (route.name) {
    case 'investigate':
      page = <InvestigatePage />;
      break;
    case 'report':
      page = <ReportPage key={route.id} id={route.id} />;
      break;
    case 'history':
      page = <HistoryPage />;
      break;
    case 'incidents':
      page = <IncidentsPage />;
      break;
    default:
      page = (
        <div className="page">
          <h1 className="page-title">Page not found</h1>
          <Empty>
            Nothing lives at this address. <a href={href('/')}>Go to Investigate</a>.
          </Empty>
        </div>
      );
  }
  return (
    <>
      <MockBanner />
      <Header />
      <main className="main" id="main">
        {page}
      </main>
      <footer className="footer">
        <span>WTD · AI-Powered Web Threat Detection &amp; Digital Trust Intelligence</span>
        <span>No automated check can prove a site or message is safe.</span>
      </footer>
      <TokenDialog />
    </>
  );
}
