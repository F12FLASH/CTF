import {
  Code2,
  FileCode,
  Database,
  BookOpen,
  Activity,
  Languages,
  GraduationCap,
  Flag,
} from "lucide-react";
import { Link, useLocation } from "wouter";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarFooter,
} from "@/components/ui/sidebar";
import { Button } from "@/components/ui/button";
import { createContext, useContext, useState } from "react";

const menuItems = [
  {
    title: "Exploit Builder",
    titleVi: "Xây Dựng Exploit",
    url: "/",
    icon: Code2,
  },
  {
    title: "Instructions",
    titleVi: "Hướng Dẫn",
    url: "/instructions",
    icon: GraduationCap,
  },
  {
    title: "Submit Flag",
    titleVi: "Nộp Flag",
    url: "/submit",
    icon: Flag,
  },
  {
    title: "Payload Generator",
    titleVi: "Tạo Payload",
    url: "/payload",
    icon: FileCode,
  },
  {
    title: "One-Gadget DB",
    titleVi: "Cơ Sở One-Gadget",
    url: "/gadgets",
    icon: Database,
  },
  {
    title: "Templates",
    titleVi: "Mẫu Exploit",
    url: "/templates",
    icon: BookOpen,
  },
  {
    title: "Attempt History",
    titleVi: "Lịch Sử Thử Nghiệm",
    url: "/history",
    icon: Activity,
  },
];

export const LanguageContext = createContext<{
  lang: "en" | "vi";
  setLang: (lang: "en" | "vi") => void;
}>({ lang: "en", setLang: () => {} });

export function useLanguage() {
  return useContext(LanguageContext);
}

export function AppSidebar() {
  const [location] = useLocation();
  const { lang, setLang } = useLanguage();

  return (
    <Sidebar>
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel className="text-xs font-medium uppercase tracking-wide">
            The Phoenix
          </SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {menuItems.map((item) => (
                <SidebarMenuItem key={item.url}>
                  <SidebarMenuButton asChild isActive={location === item.url}>
                    <Link href={item.url} data-testid={`link-${item.url.slice(1) || 'home'}`}>
                      <item.icon className="h-4 w-4" />
                      <span>{lang === "vi" ? item.titleVi : item.title}</span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
      <SidebarFooter className="p-4">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setLang(lang === "en" ? "vi" : "en")}
          className="w-full justify-start"
          data-testid="button-language-toggle"
        >
          <Languages className="h-4 w-4 mr-2" />
          <span className="text-xs">{lang === "en" ? "Tiếng Việt" : "English"}</span>
        </Button>
      </SidebarFooter>
    </Sidebar>
  );
}
