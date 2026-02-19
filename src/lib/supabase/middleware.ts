import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";

export async function updateSession(request: NextRequest) {
  // Check if environment variables are set
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  if (!supabaseUrl || !supabaseAnonKey) {
    console.error("Missing Supabase environment variables");
    // Return next response instead of error to allow site to load
    return NextResponse.next({ request });
  }

  // CSRF protection: reject mutating API requests from foreign origins
  const method = request.method;
  if (
    request.nextUrl.pathname.startsWith("/api/") &&
    method !== "GET" &&
    method !== "HEAD" &&
    method !== "OPTIONS"
  ) {
    const origin = request.headers.get("origin");
    const host = request.headers.get("host");
    
    // Allow requests on Vercel deployments (preview and production)
    const isVercel = host?.includes("vercel.app") || host?.includes("vercel.com");
    
    if (origin) {
      try {
        const originHost = new URL(origin).host;
        // Allow if same origin or Vercel deployment
        if (originHost !== host && !isVercel) {
          return NextResponse.json({ error: "Forbidden" }, { status: 403 });
        }
      } catch {
        // If it's Vercel, allow it; otherwise block
        if (!isVercel) {
          return NextResponse.json({ error: "Forbidden" }, { status: 403 });
        }
      }
    } else {
      // Allow requests without Origin header on Vercel or for certain user agents
      if (!isVercel) {
        const userAgent = request.headers.get("user-agent");
        if (userAgent && !userAgent.includes("curl") && !userAgent.includes("Postman")) {
          return NextResponse.json({ error: "Forbidden" }, { status: 403 });
        }
      }
    }
  }

  let supabaseResponse = NextResponse.next({ request });

  try {
    const supabase = createServerClient(
      supabaseUrl,
      supabaseAnonKey,
      {
        cookies: {
          getAll() {
            return request.cookies.getAll();
          },
          setAll(cookiesToSet) {
            cookiesToSet.forEach(({ name, value }) =>
              request.cookies.set(name, value)
            );
            supabaseResponse = NextResponse.next({ request });
            cookiesToSet.forEach(({ name, value, options }) =>
              supabaseResponse.cookies.set(name, value, options)
            );
          },
        },
      }
    );

    const {
      data: { user },
    } = await supabase.auth.getUser();

    const pathname = request.nextUrl.pathname;

    const publicRoutes = [
      "/",
      "/login",
      "/signup",
      "/api/auth/signup",
      "/leaderboard",
      "/markets",
      "/tv",
    ];
    const isPublicRoute = publicRoutes.some((r) => pathname === r || pathname.startsWith(r + "/"));

    // Only portfolio and admin require authentication
    const protectedRoutes = ["/portfolio", "/admin"];
    const isProtectedRoute = protectedRoutes.some((r) => pathname.startsWith(r));

    // Redirect unauthenticated users to login only for protected routes
    if (!user && isProtectedRoute) {
      const url = request.nextUrl.clone();
      url.pathname = "/login";
      return NextResponse.redirect(url);
    }

    // Redirect authenticated users away from auth pages (login/signup)
    const authPages = ["/login", "/signup", "/forgot-password"];
    const isAuthPage = authPages.some((r) => pathname.startsWith(r));
    if (user && isAuthPage) {
      const url = request.nextUrl.clone();
      url.pathname = "/";
      return NextResponse.redirect(url);
    }

    // Redirect approved users away from /verify (nothing to do there)
    if (user && pathname === "/verify") {
      try {
        const { data: profile } = await supabase
          .from("profiles")
          .select("is_approved")
          .eq("id", user.id)
          .single();

        if (profile?.is_approved) {
          const url = request.nextUrl.clone();
          url.pathname = "/";
          return NextResponse.redirect(url);
        }
      } catch (error) {
        // If database query fails, continue without redirect
        console.error("Error checking profile approval:", error);
      }
    }

    // Check approval for authenticated users accessing protected routes
    if (user && isProtectedRoute) {
      try {
        const { data: profile } = await supabase
          .from("profiles")
          .select("is_approved")
          .eq("id", user.id)
          .single();

        if (!profile?.is_approved) {
          const url = request.nextUrl.clone();
          url.pathname = "/verify";
          return NextResponse.redirect(url);
        }
      } catch (error) {
        // If database query fails, allow access (fail open)
        console.error("Error checking profile approval:", error);
      }
    }

    return supabaseResponse;
  } catch (error) {
    // Log error but don't crash - return next response to allow site to load
    console.error("Middleware error:", error);
    return NextResponse.next({ request });
  }
}
