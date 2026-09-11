const RFC3339_DATE_TIME =
    /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:[Zz]|([+-])(\d{2}):(\d{2}))$/;

/** Parse an RFC 3339 date-time, returning `NaN` for malformed input. */
export function parseRfc3339(value: string): number {
    const match = RFC3339_DATE_TIME.exec(value);
    if (!match) return Number.NaN;

    const [
        ,
        yearText,
        monthText,
        dayText,
        hourText,
        minuteText,
        secondText,
        fraction = '',
        ,
        offsetHourText,
        offsetMinuteText,
    ] = match;
    const year = Number(yearText);
    const month = Number(monthText);
    const day = Number(dayText);
    const hour = Number(hourText);
    const minute = Number(minuteText);
    const second = Number(secondText);
    const offsetHour = Number(offsetHourText ?? 0);
    const offsetMinute = Number(offsetMinuteText ?? 0);

    if (
        month < 1 ||
        month > 12 ||
        day < 1 ||
        day > daysInMonth(year, month) ||
        hour > 23 ||
        minute > 59 ||
        second > 60 ||
        offsetHour > 23 ||
        offsetMinute > 59
    ) {
        return Number.NaN;
    }

    const milliseconds = fraction ? `.${fraction.slice(0, 3).padEnd(3, '0')}` : '';
    // A leap second clamps to :59.999 and must end a UTC month, as the Rust SDK's RFC 3339 parse does.
    const secondWithFraction = second === 60 ? '59.999' : `${secondText}${milliseconds}`;
    const normalized = `${yearText}-${monthText}-${dayText}T${hourText}:${minuteText}:${secondWithFraction}${value.at(-1)?.toUpperCase() === 'Z' ? 'Z' : value.slice(-6)}`;
    const instant = Date.parse(normalized);
    if (second === 60) {
        const utc = new Date(instant);
        if (
            utc.getUTCHours() !== 23 ||
            utc.getUTCMinutes() !== 59 ||
            utc.getUTCDate() !== daysInMonth(utc.getUTCFullYear(), utc.getUTCMonth() + 1)
        ) {
            return Number.NaN;
        }
    }
    return instant;
}

function daysInMonth(year: number, month: number): number {
    if (month === 2) {
        return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28;
    }
    return month === 4 || month === 6 || month === 9 || month === 11 ? 30 : 31;
}
