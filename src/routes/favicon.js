import { Hono } from 'hono';

const faviconRouter = new Hono();

// Base64-encoded small favicon (a simple shield icon)
const FAVICON_BASE64 = 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAJlSURBVFhH7ZbBbxJhEMW/gGDpFmOLhIa0GFMvmrQeOHgyXoxHY9J48OBF/wTjxbsJMTEhsUnTm2lMUBJiTEw8eFHToEljRKGI0lJKWGAZ581ugShQoL/WpL/k5e3MfN/Ozs7siqIo4sCBxJcXLcfDUtFRz1HJq8cW5OAcO2BbkINz7IBtQQ7OsQNk5Hhx7dJ5FjgL4R9RNUtzHMu7i0gEYCHvHCwsLNgKoBNdwqXDDJfwj72uQ1Ib9QpzIcwS7IMGDaP6KWPUjWPUTdTdq+rttITZkSWs/pnBXBXY5/ZqbBlriOfm8OX3FSSKj1GsTtjKSVaQXPLg9tsYCt1FbFZHbOXwAF5+v4rpL7ehqDVbOckK5EoPnr/bRvx7HJJGlKvsmcHrfejp2oOy58OH+lVIqmQPpOxuv5fEZhPx0JZbX78J6nkzNCvf5XCQxewAtVrFf6J/QFupqXgQ4cADRl9wDQvH2OfYafqMh7qQvFeBMtSJ4GgKQ5eGYXbOGrXlIvN4H4WwV+7QOhQYbRf8gyCMjz3H8OgdODiHQad2Sd1x7jJwQ/XfZzWO7OTlrYOlnSoP3cV2G4E4e4YLJJtrzaZO9pRn9+ZdxllQ+3+2yPCZVuBjxUjvSVXrgCJ5uD0qkrs1XLdkDrSHZ4kBrvqN2p7JJ5BI7ek22UFc3JB4APNejkMaNKIQSKNzWWcJsjSX6IpFmdjG21+jsBtNtQHNJ0C8YhtZKjOYXfVgl9p+4STRHX2NV+tRFg5tSXnHE2BbkGNHkAKsj5V/BSz+iuMq0HEAAAAASUVORK5CYII=';

/**
 * Serve favicon
 */
faviconRouter.get('/', (c) => {
  // Convert base64 to binary
  const binaryData = atob(FAVICON_BASE64);
  const uint8Array = new Uint8Array(binaryData.length);
  for (let i = 0; i < binaryData.length; i++) {
    uint8Array[i] = binaryData.charCodeAt(i);
  }
  
  return new Response(uint8Array, {
    headers: {
      'Content-Type': 'image/x-icon',
      'Cache-Control': 'public, max-age=604800' // 1 week
    }
  });
});

export default faviconRouter;