export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/") {
      return new Response("OurApi is online.", {
        headers: {
          "Content-Type": "text/plain"
        }
      });
    }

    if (url.pathname === "/health") {
      return Response.json({
        status: "online",
        service: "OurApi"
      });
    }

    return Response.json({
      error: "Not Found"
    }, {
      status: 404
    });
  }
};