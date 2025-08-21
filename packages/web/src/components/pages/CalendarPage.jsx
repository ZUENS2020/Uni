import React from 'react';
import { Calendar, momentLocalizer, Views } from 'react-big-calendar';
import moment from 'moment';
import { useTranslation } from 'react-i18next';
import { mockEvents } from '../../data/events';
import 'react-big-calendar/lib/css/react-big-calendar.css';

const localizer = momentLocalizer(moment);

const CalendarPage = () => {
  const { t } = useTranslation();

  return (
    <div>
      <h2>{t('calendarTitle')}</h2>
      <div style={{ height: '500px' }}>
        <Calendar
          localizer={localizer}
          events={mockEvents}
          startAccessor="start"
          endAccessor="end"
          views={['month', 'week', 'day']}
          defaultView={Views.WEEK}
          style={{ height: 500 }}
        />
      </div>
    </div>
  );
};

export default CalendarPage;
