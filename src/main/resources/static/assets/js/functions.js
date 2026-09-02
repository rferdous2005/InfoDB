
function formatAMPM(date) {
    let hours = date.getHours();
    let minutes = date.getMinutes();
    const ampm = hours >= 12 ? 'PM' : 'AM';

    hours = hours % 12;
    hours = hours ? hours : 12; // the hour '0' should be '12'
    minutes = minutes < 10 ? '0' + minutes : minutes;

    const strTime = `${hours}:${minutes} ${ampm}`;
    return strTime;
  }

  function getFormattedDateTime() {
    const date = new Date();
    const monthNames = [
      "January", "February", "March", "April", "May", "June",
      "July", "August", "September", "October", "November", "December"
    ];

    const day = String(date.getDate()).padStart(2, '0');
    const month = monthNames[date.getMonth()];
    const year = date.getFullYear();
    const time = formatAMPM(date);

    return `${month} ${day}, ${year} ${time}`;
  }

  function updateClock() {
    $("#currentDateTime").text(getFormattedDateTime());
  }
