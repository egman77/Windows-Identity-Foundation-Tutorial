﻿using System.Web.Mvc;
using System.Web.Routing;

namespace STS
{
    public class RouteConfig
    {
        public static void RegisterRoutes(RouteCollection routes)
        {
            routes.IgnoreRoute("{resource}.axd/{*pathInfo}");
            //使用mvc属性路由
            routes.MapMvcAttributeRoutes();
        }
    }
}
