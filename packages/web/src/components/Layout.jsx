import React from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import '../App.css';

const Layout = () => {
  const { t, i18n } = useTranslation();

  const changeLanguage = (lng) => {
    i18n.changeLanguage(lng);
  };

  return (
    <div className="app-layout">
      <aside className="sidebar">
        <nav>
          <ul>
            <li>
              <NavLink to="/" end>
                {({ isActive }) => (
                  <span className={isActive ? 'active' : ''}>{t('calendarLink')}</span>
                )}
              </NavLink>
            </li>
            <li>
              <NavLink to="/tasks">
                {({ isActive }) => (
                  <span className={isActive ? 'active' : ''}>{t('tasksLink')}</span>
                )}
              </NavLink>
            </li>
          </ul>
        </nav>
        <div className="language-switcher">
          <button onClick={() => changeLanguage('en')}>English</button>
          <button onClick={() => changeLanguage('zh')}>中文</button>
        </div>
      </aside>
      <main className="main-content">
        <Outlet />
      </main>
    </div>
  );
};

export default Layout;
